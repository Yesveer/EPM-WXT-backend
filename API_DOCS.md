# API Testing with Postman

Here is how you can test the Vsay Agent Backend API using Postman.

## Prerequisites
Ensure the backend is running:
```bash
cd vsay-agent-backend
docker-compose up --build
```
*The server listens on `http://localhost:8080`*

## 1. Create User (Signup)
*   **Method**: `POST`
*   **URL**: `http://localhost:8080/api/signup`
*   **Body** (JSON):
    ```json
    {
        "username": "admin",
        "email": "admin@example.com",
        "password": "password123"
    }
    ```
*   **Response**: You will receive a `token` and `api_key`. **Save the `token` and `api_key`**.

## 2. Login (Optional if you just signed up)
*   **Method**: `POST`
*   **URL**: `http://localhost:8080/api/login`
*   **Body** (JSON):
    ```json
    {
        "email": "admin@example.com",
        "password": "password123"
    }
    ```
*   **Response**: Returns a new `token` if needed.

## 3. Configure Agent (Terminal)
Before listing machines, you need to register an agent using the `api_key` from step 1.
Open your terminal:
```bash
cd vsay-agent
./vsay-agent configure --token "YOUR_API_KEY" --host "localhost:8081" --active ...
# Follow the full configure command in the main README
sudo ./vsay-agent start
```

## 4. List Machines
*   **Method**: `GET`
*   **URL**: `http://localhost:8080/api/machines`
*   **Headers**:
    *   `Authorization`: `Bearer <YOUR_JWT_TOKEN>` (from Signup/Login response)
*   **Response**: List of connected machines. Copy the `agent_id` of a machine.

## 5. Execute Command
*   **Method**: `POST`
*   **URL**: `http://localhost:8080/api/machines/<YOUR_AGENT_ID>/command`
*   **Headers**:
    *   `Authorization`: `Bearer <YOUR_JWT_TOKEN>`
*   **Body** (JSON):
    ```json
    {
        "command": "ls -la"
    }
    ```
*   **Response**: Returns a `command_id`.

---
**Note**: Since `docker-compose` runs MongoDB, ensure you don't have a local MongoDB blocking port 27017, or adjust `docker-compose.yml`.
