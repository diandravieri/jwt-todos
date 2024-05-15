const { listTodo, createTodo, showTodo, updateTodo, deleteTodo } = require('../Models/TodoModel');

async function getTodo(req, res) {
  try {
    const userId = req.user.id;
    const todos = await listTodo(userId);
    if (todos.status) {
      res.status(200).json({
        status: todos.status,
        message: todos.message,
        data: todos.data
      });
    }
  } catch (error) {
    console.log(error);
  }
}

async function addTodo(req, res) {
  try {
    const userId = req.user.id;
    const { title, description } = req.body;
    const todo = await createTodo(title, description, userId);
    if (todo.status) {
      res.status(201).json({
        status: todo.status,
        message: todo.message,
        data: todo.data
      });
    }
  } catch (error) {
    console.log(error);
  }
}

async function todoById(req, res) {
  try {
    const todoId = req.params.id;
    const userId = req.user.id;
    const todos = await showTodo(todoId, userId);
    if (todos.status) {
      res.status(200).json({
        status: todos.status,
        message: todos.message,
        data: todos.data
      });
    }
  } catch (error) {
    console.log(error);
  }
}

async function updateTodoById(req, res) {
  try {
    const todoId = req.params.id;
    const userId = req.user.id;
    const { title, description } = req.body;
    const todo = await updateTodo(todoId, title, description, userId);
    if (todo.status) {
      res.status(200).json({
        status: todo.status,
        message: todo.message,
        data: todo.data
      });
    }
  } catch (error) {
    console.log(error);
  }
}

async function deleteTodoById(req, res) {
  try {
    const todoId = req.params.id;
    const userId = req.user.id;
    const todo = await deleteTodo(todoId, userId);
    if (todo.status) {
      res.status(200).json({
        status: todo.status,
        message: todo.message,
      });
    }
  } catch (error) {
    console.log(error);
  }
}

module.exports = {
  getTodo,
  addTodo,
  todoById,
  updateTodoById,
  deleteTodoById,
};