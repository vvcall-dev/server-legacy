use axum::{
    Json, Router,
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, broadcast};

#[derive(Deserialize)]
struct AuthRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct AuthResponse {
    success: bool,
    message: String,
    token: Option<String>,
    config_json: Option<String>,
}

#[derive(Deserialize)]
struct ConfigUpdateRequest {
    token: String,
    config_json: String,
}

struct ServerState {
    rooms: Mutex<HashMap<String, broadcast::Sender<String>>>,
    db: Mutex<Connection>,
}

type AppState = Arc<ServerState>;

#[tokio::main]
async fn main() {
    let db_path = std::env::var("DATABASE_URL").unwrap_or_else(|_| "vvcall.db".to_string());
    let db_conn = Connection::open(db_path).expect("Не удалось открыть базу данных");
    db_conn
        .execute(
            "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token TEXT,
            config_json TEXT
        )",
            (),
        )
        .expect("Не удалось создать таблицу");

    let state = Arc::new(ServerState {
        rooms: Mutex::new(HashMap::new()),
        db: Mutex::new(db_conn),
    });

    start_udp_relay();

    let app = Router::new()
        .route("/ws/:room", get(ws_handler))
        .route("/api/register", post(api_register))
        .route("/api/login", post(api_login))
        .route("/api/config", post(api_update_config))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3030").await.unwrap();
    println!("Сервер запущен на порту 3030");

    axum::serve(listener, app).await.unwrap();
}

struct FastRelay {
    rooms: RwLock<HashMap<String, HashMap<SocketAddr, Instant>>>,
    peer_to_room: RwLock<HashMap<SocketAddr, String>>,
}

fn start_udp_relay() {
    let relay = Arc::new(FastRelay {
        rooms: RwLock::new(HashMap::new()),
        peer_to_room: RwLock::new(HashMap::new()),
    });

    let relay_net = relay.clone();
    tokio::spawn(async move {
        let socket = UdpSocket::bind("0.0.0.0:3031")
            .await
            .expect("Не удалось занять порт 3031 для UDP");
        println!("SFU Ретранслятор запущен на UDP порту 3031 (Zero-allocation mode)");

        let mut buf = [0u8; 1500];

        loop {
            let (len, addr) = match socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(_) => continue,
            };

            if len == 65 && buf[0] == 0xFF {
                let room_hash = match std::str::from_utf8(&buf[1..65]) {
                    Ok(s) => s.to_string(),
                    Err(_) => continue,
                };

                let mut rooms = relay_net.rooms.write().unwrap();
                let mut peer_to_room = relay_net.peer_to_room.write().unwrap();

                rooms
                    .entry(room_hash.clone())
                    .or_default()
                    .insert(addr, Instant::now());
                peer_to_room.insert(addr, room_hash);
                continue;
            }

            let room_hash = {
                let p2r = relay_net.peer_to_room.read().unwrap();
                match p2r.get(&addr) {
                    Some(r) => r.clone(),
                    None => continue,
                }
            };

            let targets: Vec<SocketAddr> = {
                let rooms = relay_net.rooms.read().unwrap();
                if let Some(peers) = rooms.get(&room_hash) {
                    peers
                        .keys()
                        .filter(|&&peer_addr| peer_addr != addr)
                        .copied()
                        .collect()
                } else {
                    Vec::new()
                }
            };

            for target in targets {
                let _ = socket.send_to(&buf[..len], target).await;
            }
        }
    });

    let relay_cleaner = relay.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let now = Instant::now();
            let mut rooms = relay_cleaner.rooms.write().unwrap();
            let mut p2r = relay_cleaner.peer_to_room.write().unwrap();

            rooms.retain(|_, peers| {
                peers.retain(|addr, last_seen| {
                    let active = now.duration_since(*last_seen).as_secs() < 10;
                    if !active {
                        p2r.remove(addr);
                    }
                    active
                });
                !peers.is_empty()
            });
        }
    });
}

async fn api_register(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Json<AuthResponse> {
    let username = payload.username.clone();
    let password = payload.password.clone();

    let hash =
        tokio::task::spawn_blocking(move || bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap())
            .await
            .unwrap();

    let db = state.db.lock().await;
    let result = db.execute(
        "INSERT INTO users (username, password_hash, config_json) VALUES (?1, ?2, '{}')",
        (&username, &hash),
    );

    match result {
        Ok(_) => Json(AuthResponse {
            success: true,
            message: "Регистрация успешна".into(),
            token: None,
            config_json: None,
        }),
        Err(_) => Json(AuthResponse {
            success: false,
            message: "Имя пользователя уже занято".into(),
            token: None,
            config_json: None,
        }),
    }
}

async fn api_login(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Json<AuthResponse> {
    let user_data = {
        let db = state.db.lock().await;
        let mut stmt = db
            .prepare("SELECT password_hash, config_json FROM users WHERE username = ?1")
            .unwrap();
        let mut rows = stmt.query([&payload.username]).unwrap();

        if let Ok(Some(row)) = rows.next() {
            let hash: String = row.get(0).unwrap();
            let config_json: String = row.get(1).unwrap();
            Some((hash, config_json))
        } else {
            None
        }
    };

    if let Some((hash, config_json)) = user_data {
        let password = payload.password.clone();

        let is_valid =
            tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
                .await
                .unwrap();

        if is_valid {
            let token = uuid::Uuid::new_v4().to_string();

            let db = state.db.lock().await;
            db.execute(
                "UPDATE users SET token = ?1 WHERE username = ?2",
                (&token, &payload.username),
            )
            .unwrap();

            return Json(AuthResponse {
                success: true,
                message: "Успешный вход".into(),
                token: Some(token),
                config_json: Some(config_json),
            });
        }
    }

    Json(AuthResponse {
        success: false,
        message: "Неверный логин или пароль".into(),
        token: None,
        config_json: None,
    })
}

async fn api_update_config(
    State(state): State<AppState>,
    Json(payload): Json<ConfigUpdateRequest>,
) -> Json<AuthResponse> {
    let db = state.db.lock().await;

    let updated = db
        .execute(
            "UPDATE users SET config_json = ?1 WHERE token = ?2",
            (&payload.config_json, &payload.token),
        )
        .unwrap_or(0);

    if updated > 0 {
        Json(AuthResponse {
            success: true,
            message: "Настройки сохранены в облаке".into(),
            token: None,
            config_json: None,
        })
    } else {
        Json(AuthResponse {
            success: false,
            message: "Недействительный токен сессии".into(),
            token: None,
            config_json: None,
        })
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(room): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    println!("Подключение к комнате: {}", room);
    ws.on_upgrade(move |socket| handle_socket(socket, room, state))
}

async fn handle_socket(socket: WebSocket, room: String, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    let tx = {
        let mut rooms = state.rooms.lock().await;
        rooms
            .entry(room.clone())
            .or_insert_with(|| broadcast::channel(16).0)
            .clone()
    };

    let mut rx = tx.subscribe();

    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    let tx_clone = tx.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(text))) = receiver.next().await {
            let _ = tx_clone.send(text);
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    println!("Отключение от комнаты: {}", room);
}
