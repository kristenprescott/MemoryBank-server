import dotenv from "dotenv";
dotenv.config();
import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import cors from "cors";

import postRoutes from "./routes/posts.js";
import userRouter from "./routes/users.js";

const app = express();
const PORT = process.env.PORT || 8080;

app.use(bodyParser.json({ limit: "30mb", extended: true }));
app.use(bodyParser.urlencoded({ limit: "30mb", extended: true }));
app.use(express.json());
app.use((req, res, next) => {
  console.log(req.body);
  next();
});
app.use(cors());

app.use("/posts", postRoutes);
app.use("/user", userRouter);

mongoose
  .connect(process.env.MONGODB_URI, {
    useUnifiedTopology: true,
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
  })
  .then(() =>
    app.listen(PORT, () => {
      console.log("╭────────────────────────────────────╮");
      console.log("│               *ʕ•ᴥ•ʔ*              │");
      console.log("│------------------------------------│");
      console.log("│           ╭------------╮           │");
      console.log("│           |    PORT    |           │");
      console.log("│           |------------|           │");
      console.log(`│           |    ${PORT}    |           │`);
      console.log("│           ╰------------╯           │");
      console.log("╰────────────────────────────────────╯");
    })
  )
  .catch((error) => console.log(error.message));

mongoose.connection.once("connected", () =>
  console.log("Connected to Mongo - life is good B^)")
);

// ROUTES
app.get("/", (req, res) => {
  res.send(
    `
      <center>
    <div>╭──────────────────────────────────╮</div>
    <div>│꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦│</div>
    <div>│---------------------------------------------------------------------------------------│</div>
    <div>| ------------------------------------ MemoryBank ----------------------------------- |</div> <div>│---------------------------------------------------------------------------------------│</div>
    <div>│꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦│</div>
    <div>│꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦ʕ•ᴥ•ʔ꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦│</div>
    <div>│꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦꒷꒦│</div>
    <div>╰──────────────────────────────────╯</div>
  </center>
    `
  );
});
