import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import swaggerJSDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import authRouter from "./users/routes/auth.route.js";
import path from 'path'

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
        url: `https://authenticate-demo.vercel.app/api/v1`,
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
    res.setHeader("Content-Type", "application/json");
    res.send(swaggerDocs);
  });

app.get('/', (req, res) => {
  res.redirect('/api-docs'); // Redirect to Swagger UI
});

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: ['https://testing.indiantadka.eu/','http://localhost:3000'],
  credentials: true, // Allows cookies to be sent and received
}));

app.use('/api/v1', authRouter)

export default app
