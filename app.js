const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
const authRoute = require('./Routes/AuthRoute');
app.use('/api/auth', authRoute);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  // Menjalankan PORT
  console.log(`Server is running on port ${PORT}`);
});