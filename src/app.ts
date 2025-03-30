import express from "express";
import tcpdumpRoutes from "./routes/tcpdumpRoutes";

const app = express();
const PORT = process.env.PORT || 3000;

app.use("/api", tcpdumpRoutes);

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
