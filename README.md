# NestJS Authentication

<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="200" alt="Nest Logo" /></a>
</p>


![Version](https://img.shields.io/github/v/tag/Md-Tarikul-Islam-Juel/nestJS_Authentication?label=version&color=blue)
![Release](https://img.shields.io/github/v/release/Md-Tarikul-Islam-Juel/nestJS_Authentication?label=release&color=blue)
![Issues](https://img.shields.io/github/issues/Md-Tarikul-Islam-Juel/nestJS_Authentication?color=red)


<div align="center">
  <h1 style="font-size: 36px;"><strong>The Ultimate & Ready To Go Solution For User Management System</strong></h1>
</div>

The **NestJS Authentication Boilerplate** is a robust and flexible solution for implementing user authentication in your
**NestJS** projects. Empowering you with a rich feature set, it simplifies the process of managing user sign-up,
sign-in, email OTP verification, password recovery, and more.

## 🚀 Key Features: Boost your project speed

| Feature                         | Description                                                                                                | API Type | JWT Token Protection |
|---------------------------------|------------------------------------------------------------------------------------------------------------|:--------:|:--------------------:|
| **Sign-Up & Login APIs**        | Streamline user onboarding with a smooth and intuitive registration and login experience.                  |   REST   |          No          |
| **Email Verification API**      | Boost security and prevent unauthorized access through email OTP verification.                             |   REST   |          No          |
| **OTP Resend API**              | Never let users get stuck! Offer convenient OTP resend options for seamless account activation.            |   REST   |          No          |
| **Forget Password API**         | Forget passwords? No problem! Our secure recovery process helps users regain access quickly.               |   REST   |          No          |
| **Change Password API**         | Take control of your account security with effortless password changes.                                    |   REST   |         Yes          |
| **Refresh Token API**           | Allowing clients to securely refresh access token.                                                         |   REST   |         Yes          |
| **Logout API**                  | Log users out of all devices by invalidating their refresh token through logout PIN validation.            |   REST   |         Yes          |
| **Track User Last Active Time** | Capture the timestamp of the last time a user was active in the application.                               |          |                      |
| **OAuth**                       | Allowing clients to sign-in with Google, Facebook. (Note: configure your OAuth console to get credentials) |   REST   |          No          |
| **Get & Update User**           | Efficiently retrieve and update user information using GraphQL queries and mutations.                      | GraphQL  |         Yes          |

## 🌟 Technology Stack: Built with Modern Tools

- **Framework:** [NestJS](https://nestjs.com/)
- **Database:** [PostgreSQL](https://www.postgresql.org/)
- **Cache:** [Redis](https://redis.io/) - For efficient caching to improve application performance.
- **ORM:** [Prisma](https://www.prisma.io)
- **DTO Validation:** [class-validator](https://github.com/typestack/class-validator)
- **Token Management:**  JWT(JWS + JWE). Implemented [JWS](https://tools.ietf.org/html/rfc7515)
  and [JWE](https://tools.ietf.org/html/rfc7516) using the [jose](https://github.com/panva/jose)
  and [Passport](http://www.passportjs.org/) library.
- **OAuth:** [Google](https://developers.google.com/identity/protocols/oauth2)
  and [Facebook](https://developers.facebook.com/docs/facebook-login/)
- **API Documentation:** [Swagger](https://swagger.io/)
- **Database Environment:** Dockerized PostgreSQL
- **Unit Testing:** [Jest](https://jestjs.io/)
- **APIs:** REST API and GraphQL

## 📖 Swagger Documents:

<img src="https://github.com/Md-Tarikul-Islam-Juel/nestJS_Authentication/blob/main/documents/photos/swagger.png" alt="swagger" style="display: block; margin: auto;">

## 🔗 API Endpoints

Below are the key authentication API endpoints for this project:

### Auth

- **Sign-Up Endpoint:** `{{url}}/auth/signup` - Sign up user
- **Sign-In Endpoint:** `{{url}}/auth/signin` - Sign in user
- **Verify OTP Endpoint:** `{{url}}/auth/verify` - Verify OTP
- **Resend OTP Endpoint:** `{{url}}/auth/resend` - Resend OTP email
- **Forget Password Endpoint:** `{{url}}/auth/forget-password` - Forget password OTP email send
- **Change Password Endpoint:** `{{url}}/auth/change-password` - Change user password
- **Refresh Token Endpoint:** `{{url}}/auth/refresh-token` - Refresh access token
- **Start Google OAuth Flow Endpoint:** `{{url}}/auth/google` - Start Google OAuth flow
- **Google OAuth Callback Endpoint:** `{{url}}/auth/google/callback` - Google OAuth callback
- **Start Facebook OAuth Flow Endpoint:** `{{url}}/auth/facebook` - Start Facebook OAuth flow
- **Facebook OAuth Callback Endpoint:** `{{url}}/auth/facebook/callback` - Facebook OAuth callback

### GraphQL

- **GraphQL User URL:** `http://localhost:3000/user`

GraphQL Queries and Mutations

#### Get User Query

```
query GetUser {
    getUser {
        id
        email
        firstName
        lastName
    }
}
```

#### Update User

```
mutation UpdateUser {
    updateUser(data: { firstName: "Tarikul", lastName: "Juel" }) {
        id
        email
        firstName
        lastName 
    }
}
```

For more information about postman setup for GraphQL please go to the project root directory then
documents/postman/user_graphql

Replace `{{url}}` with the appropriate base URL of your API.

## 📁 Project contents:

- **Code**: Contains the source code for your project, including all necessary files and modules.
- **Postman Collection**: Provides pre-configured requests for testing and interacting with your API endpoints in
  documents folder.
- **Swagger Documentation (API Documentation)**:
  Generates interactive documentation describing your API endpoints, request parameters, response formats, and
  authentication methods.
  Accessible at **http://localhost:3000/api**

## 🚴🏿 Setup Instructions:

1. **Clone the Repository:**
    - Download or clone the repository to your local machine.

2. **Create Environment File:**
    - Navigate to the root directory.
    - Create a `.env` file based on `.env.example`.
    - Modify the variables in `.env` according to your configuration.

3. **Install Dependencies:**
    - Open your terminal.
    - Run `yarn install` or `npm install` to install project dependencies.

4. **Setup Docker:**
    - Ensure Docker is installed on your machine.
    - Run `docker-compose -f docker-compose-dev.yml up -d` to start the PostgreSQL DB container.

5. **Generate Prisma Client:**
    - Run `npx prisma generate` to generate the Prisma client.

6. **Migrate Database:**
    - Run `npx prisma migrate deploy` to apply database migrations.

7. **Import Postman Collection:**
    - Locate `nestJs_Authentication.postman_collection.json` in `documents/postman/`.
    - Import the collection into Postman.

8. **Run the Project:**
    - Start the project with `npm start` or `yarn start` or `yarn start:dev` in the terminal.

9. **Access Swagger Documentation:**
    - Open `http://localhost:3000/api` in your web browser to view the Swagger documentation.

## 🌐 Environment Setup

To configure the environment variables for this project, create a `.env` file in the root directory of your project and
add the following variables according to your data:

```
# ======================================================
# Database Configuration
# ======================================================
DATABASE_HOST=localhost
DATABASE_USER=juel
DATABASE_PASSWORD=123
DATABASE_PORT=5432
DATABASE_NAME=nest
DATABASE_URL=postgresql://${DATABASE_USER}:${DATABASE_PASSWORD}@${DATABASE_HOST}:${DATABASE_PORT}/${DATABASE_NAME}?schema=public

# ======================================================
# Docker Configuration
# ======================================================
CONTAINER_NAME=nest-Auth-DB

# ======================================================
# OTP(One-Time Password) Email Security Configuration
# ======================================================
OTP_SENDER_MAIL_HOST=smtp.office365.com
OTP_SENDER_MAIL_PORT=587
OTP_SENDER_MAIL="verification@xyz.com"
OTP_SENDER_MAIL_PASSWORD="12345"

# ======================================================
# Google OAuth Configuration
# ======================================================
GOOGLE_CLIENT_ID=1234567890123-8l6478svqjujtfuhv3p1234567890123.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-flK5CKyqQ1DEb112345678901-O0
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

# ======================================================
# Facebook OAuth Configuration
# ======================================================
FACEBOOK_CLIENT_ID=123456789012345
FACEBOOK_CLIENT_SECRET=f5df32076a1234567890159dfd854c7d
FACEBOOK_CALLBACK_URL=http://localhost:3000/auth/facebook/callback

# ======================================================
# Bcrypt Configuration
# ======================================================
BCRYPT_SALT_ROUNDS=14

# ======================================================
# OTP (One-Time Password) Configuration
# ======================================================
OTP_EXPIRE_TIME=5
OTP_MAX_FAILED_ATTEMPTS=5
OTP_LOCKOUT_TIME=5

# ======================================================
# JWT and JWE Secret Keys
# JSON Web Encryption (JWE). Each key should be exactly 32 characters long,
# ensuring they are 256 bits when properly encoded.
# ======================================================
JWE_ACCESS_TOKEN_SECRET=1234567890abcdef1234567890abcdef
JWT_ACCESS_TOKEN_SECRET=abcdefghijklmnopqrstuvwxyza123456
JWE_REFRESH_TOKEN_SECRET=abcdef1234567890abcdef1234567890
JWT_REFRESH_TOKEN_SECRET=abcdefghijklmnopqrstuvwxz1234567

# ======================================================
# Token Expiration Configuration
# ======================================================
JWE_JWT_ACCESS_TOKEN_EXPIRATION=86400s
JWE_JWT_REFRESH_TOKEN_EXPIRATION=30d

# ======================================================
# Password Validation Configuration
# ======================================================
PASSWORD_MIN_LENGTH=8
PASSWORD_MAX_LENGTH=20
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SPECIAL_CHARACTERS=true
PASSWORD_DISALLOW_REPEATING=false
PASSWORD_DISALLOW_SEQUENTIAL=false
PASSWORD_BLACKLIST_COMMON=false
PASSWORD_EXCLUDE_USERNAME=true
```

<br/><br/><br/>

<table align="center">
  <tr>
    <td align="center">
      <p style="font-size: 48px; font-weight: bold; margin: 0;">APIs Workflow</p>
    </td>
  </tr>
</table>

## Signup Process

To sign up a new user, send a POST request to the signup endpoint with the required payload.

**Endpoint:** `{{url}}/auth/signup`

**Payload:**

```json
{
  "email": "md.tarikulislamjuel@gmail.com",
  "password": "12345",
  "firstName": "tarikul",
  "lastName": "juel"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "Signup successful and please Verify your user",
  "data": {
    "id": 1,
    "email": "md.tarikulislamjuel@gmail.com",
    "firstName": "tarikul",
    "lastName": "juel"
  }
}
```

After successful signup, an OTP will be sent to the user's email for verification.

## Email(OTP) Verification Process

To verify the user's email, send a POST request to the verification endpoint with the email and OTP.

**Endpoint:** `{{url}}/auth/verify`

**Payload:**

```json
{
  "email": "md.tarikulislamjuel@gmail.com",
  "otp": "503384"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "OTP authorised",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJtZC50YXJpa3VsaXNsYW1qdWVsQGdtYWlsLmNvbSIsImZpcnN0TmFtZSI6InRhcmlrdWwiLCJsYXN0TmFtZSI6Imp1ZWwiLCJ2ZXJpZmllZCI6ZmFsc2UsImlzRm9yZ2V0UGFzc3dvcmQiOmZhbHNlLCJpYXQiOjE3MTc3Mzg3MTQsImV4cCI6MTcxNzczOTAxNH0.a6QyYCrB6DwV44USECNVpuQsSCyndt04gLyMlVB0vHI",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJtZC50YXJpa3VsaXNsYW1qdWVsQGdtYWlsLmNvbSIsImZpcnN0TmFtZSI6InRhcmlrdWwiLCJsYXN0TmFtZSI6Imp1ZWwiLCJ2ZXJpZmllZCI6ZmFsc2UsImlzRm9yZ2V0UGFzc3dvcmQiOmZhbHNlLCJpYXQiOjE3MTc3Mzg3MTQsImV4cCI6MTcyMDMzMDcxNH0.FJpya_QRP8lc1YrNpkm9biwQCdLacJ5gt1O3_ewrV0Q",
  "data": {
    "id": 1,
    "email": "md.tarikulislamjuel@gmail.com",
    "firstName": "tarikul",
    "lastName": "juel"
  }
}
```

**Notes:**

- Ensure that the OTP sent to the user is correctly used to authorize the email.
- The access token and refresh token will be provided upon successful verification.

## Signin Process

To sign in a user, send a POST request to the signin endpoint with the required payload.

**Endpoint:** `{{url}}/auth/signin`

**Payload:**

```json
{
  "email": "md.tarikulislamjuel@gmail.com",
  "password": "12345"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "Signin successful",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiZW1haWwiOiJtZC50YXJpa3VsaXNsYW1qdWVsQGdtYWlsLmNvbSIsImZpcnN0TmFtZSI6InRhcmlrdWwiLCJsYXN0TmFtZSI6Imp1ZWwiLCJ2ZXJpZmllZCI6dHJ1ZSwiaXNGb3JnZXRQYXNzd29yZCI6ZmFsc2UsImlhdCI6MTcxNzc0MDUzOSwiZXhwIjoxNzE3NzQwODM5fQ.5a6-DNGrWzepdnxYPuUR_rnEHZadoGBudOjQJwedeVQ",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiZW1haWwiOiJtZC50YXJpa3VsaXNsYW1qdWVsQGdtYWlsLmNvbSIsImZpcnN0TmFtZSI6InRhcmlrdWwiLCJsYXN0TmFtZSI6Imp1ZWwiLCJ2ZXJpZmllZCI6dHJ1ZSwiaXNGb3JnZXRQYXNzd29yZCI6ZmFsc2UsImlhdCI6MTcxNzc0MDUzOSwiZXhwIjoxNzIwMzMyNTM5fQ.8NxRnRQEwDh43dNiWcowxwGm0g0b9cx5LGPoNp4KImk",
  "data": {
    "id": 2,
    "email": "md.tarikulislamjuel@gmail.com",
    "firstName": "tarikul",
    "lastName": "juel"
  }
}

```

**Notes:**

- The access token and refresh token will be provided upon successful signin.

## Resend OTP process:

If the OTP has expired, you can resend it by sending a POST request to the resend endpoint with the user's email.

**Endpoint:** `{{url}}/auth/resend`

**Payload:**

```json
{
  "email": "md.tarikulislamjuel@gmail.com"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "OTP email send"
}
```

**Notes:**

- You can then use the **Email Verification process** to verify the email with the new OTP sent.

## Change Password Process

To change a user's password, send a POST request to the change password endpoint with the old and new passwords. This
route is protected by the **JWT Access token**.

**Endpoint:** `{{url}}/auth/change-password`

**Payload:**

```json
{
  "oldPassword": "12345",
  "newPassword": "12345@abcde"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "Your password.service.ts has been updated"
}
```

**Notes:**

- This route is protected by the JWT Access token. Ensure that the token is included in the request headers.

## Password Recovery Process

If a user forgets their password, they can initiate a password recovery process. This process involves multiple steps,
starting with requesting an OTP for verification, followed by resetting the password using the provided tokens after
verification.

### Request OTP for Password Recovery

To initiate password recovery, send a POST request to the forget-password endpoint with the user's email.

**Endpoint:** `{{url}}/auth/forget-password`

**Payload:**

```json
{
  "email": "md.tarikulislamjuel@gmail.com"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "OTP sent to your email for verification"
}
```

This will trigger an OTP to be sent to the provided email.

### Verify OTP

To verify OTP follow **Email Verification step** and you will get **accessToken**.

### Reset Password

After OTP verification you already received an accessToken. Using this accessToken now follow **Change Password Process
** and the request body will be

```json
{
  "newPassword": "12345"
}
```

here you dont need to use oldPassword field.

## 🔐 Password Validation Configuration

Easily customize password validation rules for your application using the environment variables in the `.env` file. This
allows you to enforce specific security requirements based on your project's needs.

### Configuration Options:

- **`PASSWORD_MIN_LENGTH`**: Sets the minimum password length (e.g., `8`).
- **`PASSWORD_MAX_LENGTH`**: Sets the maximum password length (e.g., `20`).
- **`PASSWORD_REQUIRE_UPPERCASE`**: Requires at least one uppercase letter (`true` or `false`).
- **`PASSWORD_REQUIRE_LOWERCASE`**: Requires at least one lowercase letter (`true` or `false`).
- **`PASSWORD_REQUIRE_NUMBERS`**: Requires at least one numeric digit (`true` or `false`).
- **`PASSWORD_REQUIRE_SPECIAL_CHARACTERS`**: Requires at least one special character (e.g., `!@#$%`) (`true` or
  `false`).
- **`PASSWORD_DISALLOW_REPEATING`**: Prevents the use of consecutive repeating characters (`true` or `false`).
- **`PASSWORD_DISALLOW_SEQUENTIAL`**: Prevents the use of sequential characters (e.g., `123`, `abc`) (`true` or
  `false`).
- **`PASSWORD_BLACKLIST_COMMON`**: Blocks common passwords like `password`, `123456` (`true` or `false`).
- **`PASSWORD_EXCLUDE_USERNAME`**: Ensures the password does not contain the username (`true` or `false`).

### Example Configuration:

Modify the following variables in your `.env` file to define your desired password policy:

```bash
PASSWORD_MIN_LENGTH=10
PASSWORD_MAX_LENGTH=20
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SPECIAL_CHARACTERS=true
PASSWORD_DISALLOW_REPEATING=false
PASSWORD_DISALLOW_SEQUENTIAL=false
PASSWORD_BLACKLIST_COMMON=true
PASSWORD_EXCLUDE_USERNAME=true
```

## 🔐 Multi-Factor Authentication (MFA) Support

This **NestJS Authentication Boilerplate** includes support for **Multi-Factor Authentication (MFA)** using email. When
MFA is enabled, after entering the correct credentials, users will receive a **One-Time Password (OTP)** via email to
complete the login process.

- **MFA Enabled**: Users receive an OTP after signing in, required to finalize the authentication.
- **Customizable**: MFA is optional and can be enabled or disabled for each user.
- **Lockout Protection**: After a set number of failed OTP attempts, the account will be temporarily locked for enhanced
  security.
- **Environment Control**: You can configure the following settings via the `.env` file:
    - `OTP_EXPIRE_TIME`: Time (in minutes) before the OTP expires. Default is 5 minutes.
    - `OTP_MAX_FAILED_ATTEMPTS`: Maximum number of allowed failed OTP attempts before account lockout. Default is 5
      attempts.
    - `OTP_LOCKOUT_TIME`: Time (in minutes) for which the account will be locked after exceeding the maximum failed OTP
      attempts. Default is 5 minutes.

MFA adds an extra layer of security by ensuring that even if a user's password is compromised, unauthorized access to
the account is still prevented.

## Logout Process Documentation

For detailed information on the logout process, see [Logout logic process](documents/logics_md/logout_process.md).

## 📦 Dockerize Your NestJS Application for Production

For detailed instructions on how to Dockerize your NestJS application for production, refer to this comprehensive guide:

check it
out: [Building and Deploying a NestJS Application with Docker Compose, PostgreSQL, and Prisma](https://medium.com/@md.tarikulislamjuel/building-and-deploying-a-nestjs-application-with-docker-compose-postgresql-and-prisma-659ba65da25b)

## 📞 Contact Information

For any inquiries or further assistance, feel free to reach out:

- **Email:** [md.tarikulislamjuel@gmail.com](mailto:md.tarikulislamjuel@gmail.com)
- **LinkedIn:** [Tarikul Islam Juel](https://www.linkedin.com/in/tarikulislamjuel/)

<p align="center">
  <a href="mailto:md.tarikulislamjuel@gmail.com"><img src="https://img.icons8.com/color/48/000000/gmail.png" alt="Gmail" style="margin: 0 15px;"/></a>
  <a href="https://www.linkedin.com/in/tarikulislamjuel/"><img src="https://img.icons8.com/color/48/000000/linkedin.png" alt="LinkedIn" style="margin: 0 15px;"/></a>
</p>




