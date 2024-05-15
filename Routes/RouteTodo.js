const express = require('express');
const router = express.Router();
const { getTodo, addTodo, todoById, updateTodoById, deleteTodoById } = require('../Controllers/ControllerTodo');

const verifyToken = require('../Middleware/VerifyToken');

router.get('/todos', verifyToken, getTodo);
router.post('/todos/create', verifyToken, addTodo);
router.get('/todos/:id', verifyToken, todoById);
router.patch('/todos/:id/update', verifyToken, updateTodoById);
router.delete('/todos/:id/delete', verifyToken, deleteTodoById);


module.exports = router;