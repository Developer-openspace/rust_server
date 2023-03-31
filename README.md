# I asked chat gpt to create a rust program 
using actix-web, argon2, jsonwebtoken and sqlx

It's response:
```
Sure! Here's an example Rust program that uses Actix-web for handling HTTP requests, Argon2 for password hashing, JSON Web Tokens (JWT) for authentication, and SQLx for interacting with a PostgreSQL database.

To run this program, you'll need to have Rust and PostgreSQL installed on your machine. You'll also need to create a new PostgreSQL database and update the DATABASE_URL constant with the correct URL.
```

Code
```rust
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use argon2::{self, Config};
use jsonwebtoken::{encode, Header, EncodingKey};
use sqlx::{postgres::PgPool, Pool, Postgres};

// Define a user struct
#[derive(sqlx::FromRow)]
struct User {
    id: i32,
    username: String,
    password: String,
}

// Define a JWT Claims struct
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// Define a login struct
#[derive(serde::Deserialize)]
struct Login {
    username: String,
    password: String,
}

async fn login(
    login: web::Json<Login>,
    pool: web::Data<PgPool>,
) -> impl Responder {
    let username = login.username.clone();
    let password = login.password.clone();
    
    let user = sqlx::query_as::<_, User>(
            r#"SELECT * FROM users WHERE username = $1"#,
            username
        )
        .fetch_one(pool.as_ref())
        .await;

    if let Ok(user) = user {
        let password_match = argon2::verify_encoded(&user.password, password.as_bytes()).unwrap_or(false);

        if password_match {
            let expiration = chrono::Utc::now()
                .checked_add_signed(chrono::Duration::minutes(30))
                .unwrap()
                .timestamp();

            let claims = Claims {
                sub: user.id.to_string(),
                exp: expiration as usize,
            };

            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret("secret".as_ref())).unwrap();

            return HttpResponse::Ok().json(token);
        }
    }

    HttpResponse::Unauthorized().finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = PgPool::connect("postgres://user:password@localhost/mydb")
        .await
        .expect("Failed to connect to database");

    HttpServer::new(move || {
        App::new()
            .data(pool.clone())
            .service(
                web::resource("/login")
                    .route(web::post().to(login)),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```