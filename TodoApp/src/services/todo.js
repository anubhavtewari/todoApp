import axios from 'axios'
import { createUrl } from '../utils'

export async function getTodoItemList() {
  try {
    // create the url
    const url = createUrl('todo/public')

    // read the token
    const token = sessionStorage['token']

    const response = await axios.get(url, {
      headers: {
        token,
      },
    })
    return response.data
  } catch (ex) {
    return { status: 'error', error: ex }
  }
}

export async function getMyTodoItems() {
  try {
    const url = createUrl('todo/my')
    const token = sessionStorage['token']
    const response = await axios.get(url, {
      headers: {
        token,
      },
    })
    return response.data
  } catch (ex) {
    return { status: 'error', error: ex }
  }
}

export async function markItemPublic(id) {
  try {
    const url = createUrl('todo/make-public/' + id)
    const token = sessionStorage['token']
    const response = await axios.patch(
      url,
      {}, // body
      {
        headers: {
          token,
        },
      }
    )
    return response.data
  } catch (ex) {
    return { status: 'error', error: ex }
  }
}

export async function markItemPrivate(id) {
  try {
    const url = createUrl('todo/make-private/' + id)
    const token = sessionStorage['token']
    const response = await axios.patch(
      url,
      {}, // body
      {
        headers: {
          token,
        },
      }
    )
    return response.data
  } catch (ex) {
    return { status: 'error', error: ex }
  }
}

export async function createTodoItem(title, details) {
  try {
    const url = createUrl('todo/')
    const token = sessionStorage['token']
    const body = {
      title,
      details,
    }
    const response = await axios.post(url, body, {
      headers: {
        token,
      },
    })
    return response.data
  } catch (ex) {
    return { status: 'error', error: ex }
  }
}
