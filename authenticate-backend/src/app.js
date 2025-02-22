import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import swaggerJSDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import authRouter from "./users/routes/auth.route.js";
import path from "path";
import sessionRouter from "./session/routes/session.routes.js";
import cartRouter from "./cart/routes/cart.routes.js";

const app = express();

const swaggerOptions = {
  swaggerDefinition: {
    openapi: "3.0.0",
    info: {
      title: "Authentication",
      version: "1.0.0",
      description: "API documentation for Authentication",
    },
    servers: [
      {
        url:
          process.env.NODE_ENV === "production"
            ? `https://authenticate-demo.vercel.app`
            : `http://localhost:${process.env.PORT || 5000}`, // Local dev URL
      },
    ],
  },
  apis: [path.resolve("src/users/routes/*.js")], // path to your API routes (adjust as necessary)
};

const swaggerDocs = swaggerJSDoc(swaggerOptions);

// Use Swagger UI middleware
app.use("/api-docs", swaggerUi.serve, (req, res) => {
  res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Swagger UI</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.1.0/swagger-ui.min.css">
      </head>
      <body>
        <div id="swagger-ui"></div>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.1.0/swagger-ui-bundle.min.js"></script>
        <script>
          window.onload = function() {
            SwaggerUIBundle({
              url: "/api-docs-json",
              dom_id: "#swagger-ui"
            });
          }
        </script>
      </body>
      </html>
    `);
});

app.get("/api-docs-json", (req, res) => {
  res.json(swaggerDocs); // Ensure the spec is sent as JSON
});

app.get("/", (req, res) => {
  res.redirect("/api-docs"); // Redirect to Swagger UI
});

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: ["https://testing.indiantadka.eu", "http://localhost:3000","https://theindiantadka.vercel.app"],
    credentials: true, // Allows cookies to be sent and received
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use("/api/v1", authRouter);
app.use("/api/v1", sessionRouter);
app.use("/api/v1", cartRouter);

export default app;
