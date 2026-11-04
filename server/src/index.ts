import { createApp } from "./app.js";

const port = Number(process.env.PORT ?? 3001);
const app = createApp();

app.listen(port, "0.0.0.0", () => {
  console.log(`webguardian-server listening on port ${port}`);
});
