const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Routes
const AuthRoute = require('./Routes/AuthRoute');
const TodoRoute = require('./Routes/RouteTodo');
app.use("/api/auth", AuthRoute);
app.use("/api", TodoRoute);

// Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});