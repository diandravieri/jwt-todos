const connection = require('../Config/Connection');
const { body, validationResult } = require('express-validator');
const runValidation = require('../Config/ValidationFields');

async function listTodo(userId) {
  try {
    const [todos] = await connection.query('select * from todos where user_id = ?', [userId]);
    return { status: true, message: 'success get todos', data: todos };
  } catch (error) {
    console.log(error);
  }
}
async function createTodo(title, description, userId) {
  // cek validasi
  const validation = [
    body("title").notEmpty().withMessage("Title is required"),
    body("description").notEmpty().withMessage("Description is required"),
  ];

  const validationErrors = await runValidation(validation, { title, description });
  if (validationErrors) {
    return { status: false, message: 'Validation errors', error: validationErrors };
  }

  try {
    const [newTodo] = await connection.query('insert into todos (title, description, user_id) values (?,?,?)', [title, description, userId]);
    return {
      status: true, message: 'Todo has been created', data: {
        id: newTodo.insertId,
        title, description, userId
      }
    }
  } catch (error) {
    console.error(error);
  }
}
async function showTodo(todoId, userId) {

  try {
    const [todo] = await connection.query('select * from todos where id =? and user_id =?', [todoId, userId]);
    return {
      status: true,
      message: 'success get todo',
      data: todo
    }
  } catch (error) {
    console.log(error);
  }
}
async function updateTodo(todoId, title, description, userId) {
  // cek validasi
  const validation = [
    body("title").notEmpty().withMessage("Title is required"),
    body("description").notEmpty().withMessage("Description is required"),
  ];

  const validationErrors = await runValidation(validation, { title, description });
  if (validationErrors) {
    return { status: false, message: 'Validation errors', error: validationErrors };
  }
  try {
    const [updatedTodo] = await connection.query('update todos set title =?, description =? where id =? and user_id =?', [title, description, todoId, userId]);
    if (updatedTodo.affectedRows === 0) {
      return {
        status: false,
        message: 'Todo not found'
      }
    }
    const result = {
      id: Number(todoId),
      title, description, userId
    }
    return {
      status: true,
      message: 'Todo has been updated',
      data: result
    }
  } catch (error) {
    console.log(error);
  }
}
async function deleteTodo(todoId, userId) {
  try {
    const [deletedTodo] = await connection.query('delete from todos where id =? and user_id =?', [todoId, userId]);
    return {
      status: true,
      message: 'Todo has been deleted',
      data: deletedTodo
    }
  } catch (error) {
    console.log(error);
  }

}

module.exports = {
  listTodo,
  createTodo,
  showTodo,
  updateTodo,
  deleteTodo
}