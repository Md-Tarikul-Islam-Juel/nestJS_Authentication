
# NestJS Authentication Boilerplate

<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="200" alt="Nest Logo" /></a>
</p>


![Version](https://img.shields.io/github/v/tag/Md-Tarikul-Islam-Juel/nestJS_Authentication?label=version&color=blue)
![Release](https://img.shields.io/github/v/release/Md-Tarikul-Islam-Juel/nestJS_Authentication?label=release&color=blue)
![Issues](https://img.shields.io/github/issues/Md-Tarikul-Islam-Juel/nestJS_Authentication?color=red)




The **NestJS Authentication Boilerplate** is a robust and flexible solution for implementing user authentication in your **NestJS** projects. Empowering you with a rich feature set, it simplifies the process of managing user sign-up, sign-in, email OTP verification, password recovery, and more.



## 🚀 Key Features: Boost your project speed

| Feature                     | Description                                                                                     |
|-----------------------------|-------------------------------------------------------------------------------------------------|
| **Sign-Up & Login APIs**    | Streamline user onboarding with a smooth and intuitive registration and login experience.       |
| **Email Verification API**  | Boost security and prevent unauthorized access through email OTP verification.                  |
| **OTP Resend API**          | Never let users get stuck! Offer convenient OTP resend options for seamless account activation. |
| **Forget Password API**     | Forget passwords? No problem! Our secure recovery process helps users regain access quickly.    |
| **Change Password API**     | Take control of your account security with effortless password changes.                         |
| **Refresh token API**       | Allowing clients to securely refresh access token.                                              |



## 📖 Swagger Documents:

<img src="https://github.com/Md-Tarikul-Islam-Juel/nestJS_Authentication/blob/main/documents/photos/swagger.png" alt="swagger" style="display: block; margin: auto;">

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
   - Run docker-compose up -d to start the PostgreSQL DB container.

5. **Import Postman Collection:**
   - Locate `nestJs_Authentication.postman_collection.json` in `documents/postman/`.
   - Import the collection into Postman.

6. **Run the Project:**
   - Start the project with `npm start` or `yarn start` in the terminal.

7. **Access Swagger Documentation:**
   - Open `http://localhost:3000/api` in your web browser to view the Swagger documentation.

