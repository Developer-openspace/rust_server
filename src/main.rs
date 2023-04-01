use actix_web::{
    App, 
    web, 
    HttpResponse, 
    HttpServer, 
    Responder,
    post,
};
use argon2::{ 
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, Postgres, Pool, FromRow};
// use rand::self;

const SECRET_KEY: &[u8] = b"my_secret_key"; // Change this to a secret key of your choice
const DATABASE_URL: &str = "postgres://admin:password123@127.0.0.1:6500/gpt"; // Change this to your PostgreSQL database URL

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct User {
    // id:i32;
    username:String,
    email: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct UserLogin {
    email: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct JwtPayload {
    // sub: i32,
    sub:String,
}

pub struct AppState{
    db:Pool<Postgres>
} 

#[post("/auth/register")]
async fn register_user(
    user: web::Json<User>,
    pool: web::Data<AppState>,
) -> impl Responder {
    let hasher = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let hash = hasher
        .hash_password(user.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    match sqlx::query_as::<_,User>(
        "INSERT INTO users ( email, password, username) VALUES ($1, $2, $3) RETURNING *",
    )
    // .bind(user.id.to_string())
    .bind(user.email.to_string())
    .bind(hash.to_string())
    .bind(user.username.to_string())
    .fetch_one(&pool.db)
    .await

    {
        Ok(row) => HttpResponse::Ok().json(row),
        Err(err) => HttpResponse::InternalServerError().json(&err.to_string()),
    }
}

#[post("/auth/login")]
async fn login_user(
    user: web::Json<User>,
    pool: web::Data<AppState>,
) -> impl Responder {
   match sqlx::query_as::<_,User>(
        "SELECT email FROM users WHERE email = $1 RETURNING *",
    )
    .bind(user.email.to_string())
    .fetch_one(&pool.db)
    .await

    {
        Ok(row) => {
            let hasher = Argon2::default();
            let password_hash = PasswordHash::new(row.password.as_str()).unwrap();

            match hasher.verify_password(user.password.as_bytes(), &password_hash) {
                Ok(_) => {
                    let payload = JwtPayload { sub: row.email};
                    let token = encode(
                        &Header::default(),
                        &payload,
                        &EncodingKey::from_secret(SECRET_KEY),
                    )
                    .unwrap();
                    HttpResponse::Ok().body(token)
                },
                Err(err) => HttpResponse::Unauthorized().json(&err.to_string()),
            }
        },
        Err(err) => HttpResponse::Unauthorized().json(&err.to_string()),
    }
}

async fn auth_handler(
    token: web::Json<String>,
) -> impl Responder {
    let token_data = decode::<JwtPayload>(
        &token,
        &DecodingKey::from_secret(SECRET_KEY),
        &Validation::default(),
    );

    match token_data {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(_) => HttpResponse::Unauthorized().finish(),
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(DATABASE_URL)
        .await
        .unwrap();

    HttpServer::new(move||{
        App::new()
        .app_data(web::Data::new(AppState {db:pool.clone()}))
        .service(register_user)
    })
    .bind(("127.0.0.1",8000))?
    .run()
    .await
}
