import "dotenv/config";
import connectDB from "./src/config/mongodb.js";
// import app from "./src/app.js";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import swaggerJSDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import authRouter from "./src/users/routes/auth.route.js";

// connectDB()
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
        url: `http://localhost:${process.env.PORT || 5000}`|| 'https://authenticate-demo.vercel.app/api/v1',
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
  methods: ['GET', 'POST', 'PUT','DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use('/api', authRouter)


connectDB()
.then(() => {
  app.listen(process.env.PORT || 5000, () => {
      console.log(`⚙️  Server is running at port : ${process.env.PORT}`);
  })
})
.catch((err) => {
  console.log("MONGO db connection failed !!! ", err);
})
