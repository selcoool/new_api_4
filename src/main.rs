

// CREATE TABLE users (
//     id INT AUTO_INCREMENT PRIMARY KEY,
//     email VARCHAR(255) UNIQUE,
//     password TEXT,
//     role VARCHAR(20)
// );

// CREATE TABLE products (
//     id INT AUTO_INCREMENT PRIMARY KEY,
//     name VARCHAR(255),
//     price DOUBLE
// );


use actix_web::{
    post, get, web, App, HttpServer, HttpResponse, HttpRequest,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures_util::future::{ok, Ready, LocalBoxFuture};
use serde::{Deserialize, Serialize};
use sqlx::{MySqlPool, mysql::MySqlPoolOptions};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use chrono::{Utc, Duration};
use std::env;

/* ================= ROLE ================= */

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
enum Role {
    Admin,
    Editor,
    User,
}

/* ================= INPUT ================= */

#[derive(Deserialize)]
struct AuthBody {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct ProductBody {
    name: String,
    price: f64,
}

/* ================= OUTPUT ================= */

#[derive(Serialize)]
struct Product {
    id: i32,
    name: Option<String>,
    price: Option<f64>,
}

/* ================= CLAIMS ================= */

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    user_id: i32,
    role: Role,
    exp: usize,
}

/* ================= CONFIG ================= */

fn secret() -> String {
    env::var("JWT_SECRET").unwrap()
}

fn expire_hours() -> i64 {
    env::var("JWT_EXPIRE_HOURS")
        .unwrap_or("24".to_string())
        .parse()
        .unwrap()
}

/* ================= JWT ================= */

fn create_token(user_id: i32, role: Role) -> String {
    let exp = Utc::now()
        .checked_add_signed(Duration::hours(expire_hours()))
        .unwrap()
        .timestamp() as usize;

    let claims = Claims { user_id, role, exp };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret().as_bytes()),
    )
    .unwrap()
}

fn verify_token(token: &str) -> Option<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret().as_bytes()),
        &Validation::default(),
    )
    .ok()
    .map(|d| d.claims)
}

/* ================= ROLE PARSER ================= */

fn parse_role(role: &str) -> Role {
    match role {
        "admin" => Role::Admin,
        "editor" => Role::Editor,
        _ => Role::User,
    }
}

/* ================= MIDDLEWARE ================= */

pub struct JwtMiddleware;

impl<S, B> Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtMiddlewareService { service })
    }
}

pub struct JwtMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for JwtMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &self,
        ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auth = req.headers().get("Authorization");

        if auth.is_none() {
            return Box::pin(async {
                Err(actix_web::error::ErrorUnauthorized("No token"))
            });
        }

        let token = auth.unwrap().to_str().unwrap();
        let token = token.strip_prefix("Bearer ").unwrap_or("");

        let claims = match verify_token(token) {
            Some(c) => c,
            None => {
                return Box::pin(async {
                    Err(actix_web::error::ErrorUnauthorized("Invalid token"))
                });
            }
        };

        // ✅ NO mut warning anymore (move + clone approach)
        req.extensions_mut().insert(claims);

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

/* ================= HELPERS ================= */

fn get_user(req: &HttpRequest) -> Option<Claims> {
    req.extensions().get::<Claims>().cloned()
}

/* ================= REGISTER ================= */

#[post("/register")]
async fn register(
    pool: web::Data<MySqlPool>,
    body: web::Json<AuthBody>,
) -> HttpResponse {
    let hashed = hash(&body.password, DEFAULT_COST).unwrap();

    let result = sqlx::query(
        "INSERT INTO users (email, password, role) VALUES (?, ?, 'user')",
    )
    .bind(&body.email)
    .bind(hashed)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("register success"),
        Err(e) => HttpResponse::BadRequest().body(e.to_string()),
    }
}

/* ================= LOGIN ================= */

#[post("/login")]
async fn login(
    pool: web::Data<MySqlPool>,
    body: web::Json<AuthBody>,
) -> HttpResponse {
    let user = sqlx::query!(
        "SELECT id, password, role FROM users WHERE email = ?",
        body.email
    )
    .fetch_one(pool.get_ref())
    .await;

    if user.is_err() {
        return HttpResponse::Unauthorized().body("user not found");
    }

    let user = user.unwrap();

    let password = match user.password {
        Some(p) => p,
        None => return HttpResponse::Unauthorized().body("no password"),
    };

    let ok = verify(&body.password, &password).unwrap_or(false);

    if !ok {
        return HttpResponse::Unauthorized().body("wrong password");
    }

    let role = parse_role(&user.role.unwrap_or("user".to_string()));

    let token = create_token(user.id, role);

    HttpResponse::Ok().json(serde_json::json!({
        "token": token
    }))
}

/* ================= CREATE PRODUCT ================= */

#[post("/products")]
async fn create_product(
    req: HttpRequest,
    pool: web::Data<MySqlPool>,
    body: web::Json<ProductBody>,
) -> HttpResponse {

    let user = match get_user(&req) {
        Some(u) => u,
        None => return HttpResponse::Unauthorized().body("No user"),
    };

    if !(user.role == Role::Admin || user.role == Role::Editor) {
        return HttpResponse::Forbidden().body("Forbidden");
    }

    let result = sqlx::query(
        "INSERT INTO products (name, price) VALUES (?, ?)",
    )
    .bind(&body.name)
    .bind(body.price)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("product created"),
        Err(e) => HttpResponse::BadRequest().body(e.to_string()),
    }
}

/* ================= GET PRODUCTS ================= */

#[get("/products")]
async fn get_products(pool: web::Data<MySqlPool>) -> HttpResponse {
    let rows = sqlx::query_as!(
        Product,
        "SELECT id, name, price FROM products"
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap();

    HttpResponse::Ok().json(rows)
}

/* ================= MAIN ================= */

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    let pool = MySqlPoolOptions::new()
        .connect(&env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    println!("SERVER RUNNING => 8080");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(register)
            .service(login)
            .service(get_products)
            .service(
                web::scope("")
                    .wrap(JwtMiddleware)
                    .service(create_product)
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}




// CREATE TABLE users (
//     id INT AUTO_INCREMENT PRIMARY KEY,
//     email VARCHAR(255) UNIQUE,
//     password TEXT,
//     role VARCHAR(20)
// );

// CREATE TABLE products (
//     id INT AUTO_INCREMENT PRIMARY KEY,
//     name VARCHAR(255),
//     price DOUBLE
// );




// use actix_web::{
//     post, get, web, App, HttpServer, HttpResponse, HttpRequest,
// };
// use serde::{Deserialize, Serialize};
// use sqlx::{MySqlPool, mysql::MySqlPoolOptions};
// use bcrypt::{hash, verify, DEFAULT_COST};
// use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
// use chrono::{Utc, Duration};
// use std::env;

// /* ================= ROLE ================= */

// #[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
// enum Role {
//     Admin,
//     Editor,
//     User,
// }

// /* ================= INPUT ================= */

// #[derive(Deserialize)]
// struct AuthBody {
//     email: String,
//     password: String,
// }

// #[derive(Deserialize)]
// struct ProductBody {
//     name: String,
//     price: f64,
// }

// /* ================= OUTPUT ================= */

// #[derive(Serialize)]
// struct Product {
//     id: i32,
//     name: Option<String>,
//     price: Option<f64>,
// }

// /* ================= JWT CLAIMS ================= */

// #[derive(Debug, Serialize, Deserialize)]
// struct Claims {
//     user_id: i32,
//     role: Role,
//     exp: usize,
// }

// /* ================= CONFIG ================= */

// fn secret() -> String {
//     env::var("JWT_SECRET").unwrap()
// }

// fn expire_hours() -> i64 {
//     env::var("JWT_EXPIRE_HOURS")
//         .unwrap_or("24".to_string())
//         .parse()
//         .unwrap()
// }

// /* ================= TOKEN ================= */

// fn create_token(user_id: i32, role: Role) -> String {
//     let exp = Utc::now()
//         .checked_add_signed(Duration::hours(expire_hours()))
//         .unwrap()
//         .timestamp() as usize;

//     let claims = Claims { user_id, role, exp };

//     encode(
//         &Header::default(),
//         &claims,
//         &EncodingKey::from_secret(secret().as_bytes()),
//     )
//     .unwrap()
// }

// fn verify_token(token: &str) -> Option<Claims> {
//     decode::<Claims>(
//         token,
//         &DecodingKey::from_secret(secret().as_bytes()),
//         &Validation::default(),
//     )
//     .ok()
//     .map(|d| d.claims)
// }

// /* ================= ROLE PARSER ================= */

// fn parse_role(role: &str) -> Role {
//     match role {
//         "admin" => Role::Admin,
//         "editor" => Role::Editor,
//         _ => Role::User,
//     }
// }


// // fn parse_role(role: &str) -> Option<Role> {
// //     match role {
// //         "admin" => Some(Role::Admin),
// //         "editor" => Some(Role::Editor),
// //         "user" => Some(Role::User),
// //         _ => None,
// //     }
// // }


// /* ================= AUTH CHECK ================= */

// fn require_role(req: &HttpRequest, allowed: &[Role]) -> Result<Claims, HttpResponse> {
//     let auth = req.headers().get("Authorization");

//     if auth.is_none() {
//         return Err(HttpResponse::Unauthorized().body("No token"));
//     }

//     let token = auth.unwrap().to_str().unwrap();
//     let token = token.strip_prefix("Bearer ").unwrap_or("");

//     match verify_token(token) {
//         Some(claims) => {
//             if !allowed.contains(&claims.role) {
//                 return Err(HttpResponse::Forbidden().body("Forbidden"));
//             }
//             Ok(claims)
//         }
//         None => Err(HttpResponse::Unauthorized().body("Invalid token")),
//     }
// }

// /* ================= REGISTER ================= */

// #[post("/register")]
// async fn register(
//     pool: web::Data<MySqlPool>,
//     body: web::Json<AuthBody>,
// ) -> HttpResponse {
//     let hashed = hash(&body.password, DEFAULT_COST).unwrap();

//     let result = sqlx::query(
//         "INSERT INTO users (email, password, role) VALUES (?, ?, 'user')",
//     )
//     .bind(&body.email)
//     .bind(hashed)
//     .execute(pool.get_ref())
//     .await;

//     match result {
//         Ok(_) => HttpResponse::Ok().body("register success"),
//         Err(e) => HttpResponse::BadRequest().body(e.to_string()),
//     }
// }

// /* ================= LOGIN ================= */

// #[post("/login")]
// async fn login(
//     pool: web::Data<MySqlPool>,
//     body: web::Json<AuthBody>,
// ) -> HttpResponse {
//     let user = sqlx::query!(
//         "SELECT id, password, role FROM users WHERE email = ?",
//         body.email
//     )
//     .fetch_one(pool.get_ref())
//     .await;

//     if user.is_err() {
//         return HttpResponse::Unauthorized().body("user not found");
//     }

//     let user = user.unwrap();

//     let password = match user.password {
//         Some(p) => p,
//         None => return HttpResponse::Unauthorized().body("no password"),
//     };

//     let role = parse_role(&user.role.unwrap_or("user".to_string()));

//     let ok = verify(&body.password, &password).unwrap_or(false);

//     if !ok {
//         return HttpResponse::Unauthorized().body("wrong password");
//     }

//     let token = create_token(user.id, role);

//     HttpResponse::Ok().json(serde_json::json!({
//         "token": token
//     }))
// }

// /* ================= CREATE PRODUCT (ADMIN + EDITOR) ================= */

// #[post("/products")]
// async fn create_product(
//     req: HttpRequest,
//     pool: web::Data<MySqlPool>,
//     body: web::Json<ProductBody>,
// ) -> HttpResponse {
//     let _claims = match require_role(&req, &[Role::Admin, Role::Editor]) {
//         Ok(c) => c,
//         Err(e) => return e,
//     };

//     let result = sqlx::query(
//         "INSERT INTO products (name, price) VALUES (?, ?)",
//     )
//     .bind(&body.name)
//     .bind(body.price)
//     .execute(pool.get_ref())
//     .await;

//     match result {
//         Ok(_) => HttpResponse::Ok().body("product created"),
//         Err(e) => HttpResponse::BadRequest().body(e.to_string()),
//     }
// }

// /* ================= GET PRODUCTS (ALL ROLES) ================= */

// #[get("/products")]
// async fn get_products(pool: web::Data<MySqlPool>) -> HttpResponse {
//     let rows = sqlx::query_as!(
//         Product,
//         r#"
//         SELECT id, name, price
//         FROM products
//         "#
//     )
//     .fetch_all(pool.get_ref())
//     .await
//     .unwrap();

//     HttpResponse::Ok().json(rows)
// }

// /* ================= MAIN ================= */

// #[actix_web::main]
// async fn main() -> std::io::Result<()> {
//     dotenvy::dotenv().ok();

//     let pool = MySqlPoolOptions::new()
//         .connect(&env::var("DATABASE_URL").unwrap())
//         .await
//         .unwrap();

//     println!("SERVER RUNNING => 8080");

//     HttpServer::new(move || {
//         App::new()
//             .app_data(web::Data::new(pool.clone()))
//             .service(register)
//             .service(login)
//             .service(create_product)
//             .service(get_products)
//     })
//     .bind("127.0.0.1:8080")?
//     .run()
//     .await
// }













// use actix_web::{
//     post, get, web, App, HttpServer, HttpResponse, HttpRequest,
// };
// use serde::{Deserialize, Serialize};
// use sqlx::{MySqlPool, mysql::MySqlPoolOptions};
// use bcrypt::{hash, verify, DEFAULT_COST};
// use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
// use chrono::{Utc, Duration};
// use std::env;

// /* ================= INPUT ================= */

// #[derive(Deserialize)]
// struct AuthBody {
//     email: String,
//     password: String,
// }

// #[derive(Deserialize)]
// struct ProductBody {
//     name: String,
//     price: f64,
// }

// /* ================= OUTPUT (FIX SQLx ERROR) ================= */

// #[derive(Serialize)]
// struct Product {
//     id: i32,
//     name: Option<String>,
//     price: Option<f64>,
// }

// /* ================= JWT ================= */

// #[derive(Debug, Serialize, Deserialize)]
// struct Claims {
//     user_id: i32,
//     role: String,
//     exp: usize,
// }

// fn secret() -> String {
//     env::var("JWT_SECRET").unwrap()
// }

// fn expire_hours() -> i64 {
//     env::var("JWT_EXPIRE_HOURS")
//         .unwrap_or("24".to_string())
//         .parse()
//         .unwrap()
// }

// fn create_token(user_id: i32, role: String) -> String {
//     let exp = Utc::now()
//         .checked_add_signed(Duration::hours(expire_hours()))
//         .unwrap()
//         .timestamp() as usize;

//     let claims = Claims { user_id, role, exp };

//     encode(
//         &Header::default(),
//         &claims,
//         &EncodingKey::from_secret(secret().as_bytes()),
//     )
//     .unwrap()
// }

// fn verify_token(token: &str) -> Option<Claims> {
//     decode::<Claims>(
//         token,
//         &DecodingKey::from_secret(secret().as_bytes()),
//         &Validation::default(),
//     )
//     .ok()
//     .map(|d| d.claims)
// }

// /* ================= ADMIN CHECK ================= */

// fn check_admin(req: &HttpRequest) -> Result<Claims, HttpResponse> {
//     let auth = req.headers().get("Authorization");

//     if auth.is_none() {
//         return Err(HttpResponse::Unauthorized().body("No token"));
//     }

//     let token = auth.unwrap().to_str().unwrap();
//     let token = token.strip_prefix("Bearer ").unwrap_or("");

//     match verify_token(token) {
//         Some(claims) => {
//             if claims.role != "admin" {
//                 return Err(HttpResponse::Forbidden().body("Admin only"));
//             }
//             Ok(claims)
//         }
//         None => Err(HttpResponse::Unauthorized().body("Invalid token")),
//     }
// }

// /* ================= REGISTER ================= */

// #[post("/register")]
// async fn register(
//     pool: web::Data<MySqlPool>,
//     body: web::Json<AuthBody>,
// ) -> HttpResponse {
//     let hashed = hash(&body.password, DEFAULT_COST).unwrap();

//     let result = sqlx::query(
//         "INSERT INTO users (email, password, role) VALUES (?, ?, 'user')",
//     )
//     .bind(&body.email)
//     .bind(hashed)
//     .execute(pool.get_ref())
//     .await;

//     match result {
//         Ok(_) => HttpResponse::Ok().body("register success"),
//         Err(e) => HttpResponse::BadRequest().body(e.to_string()),
//     }
// }

// /* ================= LOGIN ================= */

// #[post("/login")]
// async fn login(
//     pool: web::Data<MySqlPool>,
//     body: web::Json<AuthBody>,
// ) -> HttpResponse {
//     let user = sqlx::query!(
//         "SELECT id, password, role FROM users WHERE email = ?",
//         body.email
//     )
//     .fetch_one(pool.get_ref())
//     .await;

//     if user.is_err() {
//         return HttpResponse::Unauthorized().body("user not found");
//     }

//     let user = user.unwrap();

//     let password = match user.password {
//         Some(p) => p,
//         None => return HttpResponse::Unauthorized().body("no password"),
//     };

//     let role = user.role.unwrap_or("user".to_string());

//     let ok = verify(&body.password, &password).unwrap_or(false);

//     if !ok {
//         return HttpResponse::Unauthorized().body("wrong password");
//     }

//     let token = create_token(user.id, role);

//     HttpResponse::Ok().json(serde_json::json!({
//         "token": token
//     }))
// }

// /* ================= CREATE PRODUCT (ADMIN ONLY) ================= */

// #[post("/products")]
// async fn create_product(
//     req: HttpRequest,
//     pool: web::Data<MySqlPool>,
//     body: web::Json<ProductBody>,
// ) -> HttpResponse {
//     let _admin = match check_admin(&req) {
//         Ok(a) => a,
//         Err(e) => return e,
//     };

//     let result = sqlx::query(
//         "INSERT INTO products (name, price) VALUES (?, ?)",
//     )
//     .bind(&body.name)
//     .bind(body.price)
//     .execute(pool.get_ref())
//     .await;

//     match result {
//         Ok(_) => HttpResponse::Ok().body("product created"),
//         Err(e) => HttpResponse::BadRequest().body(e.to_string()),
//     }
// }

// /* ================= GET PRODUCTS ================= */

// #[get("/products")]
// async fn get_products(pool: web::Data<MySqlPool>) -> HttpResponse {
//     let rows = sqlx::query_as!(
//         Product,
//         r#"
//         SELECT id, name, price
//         FROM products
//         "#
//     )
//     .fetch_all(pool.get_ref())
//     .await
//     .unwrap();

//     HttpResponse::Ok().json(rows)
// }

// /* ================= MAIN ================= */

// #[actix_web::main]
// async fn main() -> std::io::Result<()> {
//     dotenvy::dotenv().ok();

//     let pool = MySqlPoolOptions::new()
//         .connect(&env::var("DATABASE_URL").unwrap())
//         .await
//         .unwrap();

//     println!("SERVER RUNNING => 8080");

//     HttpServer::new(move || {
//         App::new()
//             .app_data(web::Data::new(pool.clone()))
//             .service(register)
//             .service(login)
//             .service(create_product)
//             .service(get_products)
//     })
//     .bind("127.0.0.1:8080")?
//     .run()
//     .await
// }