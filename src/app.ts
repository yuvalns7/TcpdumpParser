import express from "express";
import tcpdumpRoutes from "./routes/tcpdumpRoutes";
import { ensureDirectoriesExist } from "./services/fileService";

const app = express();
const PORT = process.env.PORT || 3000;
ensureDirectoriesExist();

app.use("/api", tcpdumpRoutes);

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
