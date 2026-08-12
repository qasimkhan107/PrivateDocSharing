# PrivateAI Agent - Initial Project Skeleton

Minimal foundation for the PrivateAI Agent project. This repository contains a Node/Express backend (ES modules) connected to MongoDB and a Vite + React client scaffold.

This commit is a one-time setup on main. Four feature branches should be created from main and implement features independently:
- feat/roles-requests
- feat/agent
- feat/encryption
- feat/frontend

Stage 0 initial skeleton is present. Stage 1 adds the authentication foundation: registration, login, bcrypt password hashing, JWT creation/verification, and a temporary protected `/api/auth/me` endpoint. Stage 2 defines the organization role data model with explicit `owner`, `reviewer`, and `member` roles. Stage 3 adds reusable role authorization middleware via `requireRole(...)` on top of `protect`. Documents, requests, messaging, notifications, AI, encryption, and signatures are not implemented yet.

Repository layout

private-ai-agent/
├── client/                # Vite + React frontend scaffold
├── server/                # Node/Express backend (ES modules)
│   ├── src/
│   │   ├── config/
│   │   ├── controllers/
│   │   ├── middleware/
│   │   ├── models/
│   │   ├── routes/
│   │   ├── services/
│   │   ├── sockets/
│   │   ├── utils/
│   │   ├── validators/
│   │   ├── app.js
│   │   └── server.js
│   ├── .env               # NOT committed to git (included here as local placeholder)
│   ├── .env.example
│   └── package.json
├── uploads/               # tracked directory for uploaded files (.gitkeep used)
├── .gitignore
└── README.md

Getting started (development)

1. Backend

- Change to the server folder
  cd server

- Install dependencies
  npm install

- Configure environment
  Copy .env.example to .env and set MONGODB_URI (the included .env has a placeholder). Example:

  PORT=5000
  MONGODB_URI=mongodb://localhost:27017/privateai
  JWT_SECRET=replace-with-a-long-random-secret
  JWT_EXPIRES_IN=1d

- Run in development mode (uses nodemon)
  npm run dev

- Start (production)
  npm start

Health check

GET http://localhost:5000/api/health

Response:
{
  "success": true,
  "message": "PrivateAI Agent API is running"
}

Authentication endpoints

- POST http://localhost:5000/api/auth/register
  Body: `{ "name": "Owner", "email": "owner@example.com", "password": "secret123", "organizationName": "Example Org" }`
- POST http://localhost:5000/api/auth/login
  Body: `{ "email": "owner@example.com", "password": "secret123" }`
- GET http://localhost:5000/api/auth/me
  Header: `Authorization: Bearer <token>`

Auth responses return a JWT and safe user fields only; passwords are never returned.

2. Frontend

- Change to the client folder
  cd client

- Install dependencies
  npm install

- Run dev server
  npm run dev

Role authorization middleware

- `protect` verifies `Authorization: Bearer <token>` and attaches the JWT identity to `req.user`.
- `requireRole(allowedRoles)` should run after `protect`, for example: `protect, requireRole(['owner', 'reviewer'])`.
- Role checks use only the verified `req.user.role`; request body role values are ignored.
- Unauthorized authenticated roles receive `403`; unauthenticated requests receive `401`.

Notes

- Stage 1 authentication is implemented.
- Stage 2 role definitions are implemented with enum values: `owner`, `reviewer`, and `member`.
- Stage 3 role authorization middleware is implemented.
- Later feature work is not implemented yet.
- The server is ES modules (package.json has "type": "module").
- server/.env is included here as a placeholder but should not be committed in a real project; .gitignore prevents it from being tracked.

If you are the lead engineer running this for the team, confirm you have pushed this commit to main and notify the team that they can branch off now.