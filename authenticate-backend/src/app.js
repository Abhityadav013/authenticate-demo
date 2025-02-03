import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import swaggerJSDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import authRouter from "./users/routes/auth.route.js";

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
        url: `http://localhost:${process.env.PORT || 5000}`,
      },
    ],
  },
  apis: ["./src/users/routes/*.js"], // path to your API routes (adjust as necessary)
};

const swaggerDocs = swaggerJSDoc(swaggerOptions);

// Use Swagger UI middleware
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));

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
