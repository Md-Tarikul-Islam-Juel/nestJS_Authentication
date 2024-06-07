
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

The **NestJS Authentication Boilerplate** is a robust and flexible solution for implementing user authentication in your **NestJS** projects. Empowering you with a rich feature set, it simplifies the process of managing user sign-up, sign-in, email OTP verification, password recovery, and more.



## 🚀 Key Features: Boost your project speed

| Feature                    | Description                                                                                         |
|----------------------------|-----------------------------------------------------------------------------------------------------|
| **Sign-Up & Login APIs**   | Streamline user onboarding with a smooth and intuitive registration and login experience.           |
| **Email Verification API** | Boost security and prevent unauthorized access through email OTP verification.                      |
| **OTP Resend API**         | Never let users get stuck! Offer convenient OTP resend options for seamless account activation.     |
| **Forget Password API**    | Forget passwords? No problem! Our secure recovery process helps users regain access quickly.        |
| **Change Password API**    | Take control of your account security with effortless password changes.                             |
| **Refresh token API**      | Allowing clients to securely refresh access token.                                                  |
| **OAuth(Google sign-in)**  | Allowing clients to sign-in with google.(Note: config your google cloud console to get credentials) |
| **OAuth(Facebook sign-in)**| Allowing clients to sign-in with Facebook.(Note: config your meta developer console to get credentials) |



## 📖 Swagger Documents:

<img src="https://github.com/Md-Tarikul-Islam-Juel/nestJS_Authentication/blob/main/documents/photos/swagger.png" alt="swagger" style="display: block; margin: auto;">


## 🔗 API Endpoints

Below are the key authentication API endpoints for this project:

- **Sign-Up Endpoint:** `{{url}}/auth/signup`
- **Sign-In Endpoint:** `{{url}}/auth/signin`
- **Email Verification Endpoint:** `{{url}}/auth/verify`
- **Resend OTP Endpoint:** `{{url}}/auth/resend`
- **Forget Password Endpoint:** `{{url}}/auth/forget-password`
- **Change Password Endpoint:** `{{url}}/auth/change-password`
- **Refresh Token Endpoint:** `{{url}}/auth/refresh-token`
- **User Information Endpoint:** `{{url}}/user/me`

Replace `{{url}}` with the appropriate base URL of your API.

## 📁 Project contents:
- **Code**: Contains the source code for your project, including all necessary files and modules.
- **Postman Collection**: Provides pre-configured requests for testing and interacting with your API endpoints in documents folder.
- **Swagger Documentation (API Documentation)**:
  Generates interactive documentation describing your API endpoints, request parameters, response formats, and authentication methods.
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
   - Run `docker-compose up -d` to start the PostgreSQL DB container.

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

To configure the environment variables for this project, create a `.env` file in the root directory of your project and add the following variables according to your data:

```
# Database Configuration
DATABASE_HOST=localhost
DATABASE_USER=juel
DATABASE_PASSWORD=123
DATABASE_PORT=5432
DATABASE_NAME=nest
DATABASE_URL=postgresql://${DATABASE_USER}:${DATABASE_PASSWORD}@${DATABASE_HOST}:${DATABASE_PORT}/${DATABASE_NAME}?schema=public

# DOCKER
CONTAINER_NAME=nest-Auth-DB

# JWT Secret Keys
JWT_ACCESS_TOKEN_SECRET=bababababababababababababababab
JWT_REFRESH_TOKEN_SECRET=abababababababababababababababa

# OTP Security Configuration
OTP_SENDER_MAIL_HOST=smtp.office365.com
OTP_SENDER_MAIL="verification@gmail.com"
OTP_SENDER_MAIL_PASSWORD="12345"

# Google OAuth Configuration
GOOGLE_CLIENT_ID=170710067200-7l65778saggjugtfufv3pgp6d4u00j466.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GaCaa-flK5CKsqQ1DEd1o3144PZtur5-O0
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

# Facebook OAuth Configuration
FACEBOOK_CLIENT_ID=474444614456484
FACEBOOK_CLIENT_SECRET=f5df32576af581129567b62dfd854c8d
FACEBOOK_CALLBACK_URL=http://localhost:3000/auth/facebook/callback

# Bcrypt Configuration
BCRYPT_SALT_ROUNDS=14

# OTP Expiry Time (in minutes)
OTP_EXPIRE_TIME=5

# JWT Token Expiration Time
JWT_ACCESS_TOKEN_EXPIRATION=300s
JWT_REFRESH_TOKEN_EXPIRATION=30d
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

To change a user's password, send a POST request to the change password endpoint with the old and new passwords. This route is protected by the **JWT Access token**.

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
    "message": "Your password has been updated"
}
```
**Notes:**
- This route is protected by the JWT Access token. Ensure that the token is included in the request headers.


## Password Recovery Process

If a user forgets their password, they can initiate a password recovery process. This process involves multiple steps, starting with requesting an OTP for verification, followed by resetting the password using the provided tokens after verification.

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

After OTP verification you already received an accessToken. Using this accessToken now follow **Change Password Process** and the request body will be
```json
{
    "newPassword": "12345"
}
```

here you dont need to use oldPassword field.

## 📦 Dockerize Your NestJS Application for Production

For detailed instructions on how to Dockerize your NestJS application for production, refer to this comprehensive guide:

check it out: [Building and Deploying a NestJS Application with Docker Compose, PostgreSQL, and Prisma](https://medium.com/@md.tarikulislamjuel/building-and-deploying-a-nestjs-application-with-docker-compose-postgresql-and-prisma-659ba65da25b)


## 📞 Contact Information

For any inquiries or further assistance, feel free to reach out:

- **Email:** [md.tarikulislamjuel@gmail.com](mailto:md.tarikulislamjuel@gmail.com)
- **LinkedIn:** [Tarikul Islam Juel](https://www.linkedin.com/in/tarikulislamjuel/)



<p align="center">
  <a href="mailto:md.tarikulislamjuel@gmail.com"><img src="https://img.icons8.com/color/48/000000/gmail.png" alt="Gmail" style="margin: 0 15px;"/></a>
  <a href="https://www.linkedin.com/in/tarikulislamjuel/"><img src="https://img.icons8.com/color/48/000000/linkedin.png" alt="LinkedIn" style="margin: 0 15px;"/></a>
</p>



