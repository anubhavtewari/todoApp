import axios from 'axios'
import { createUrl } from '../utils'

export async function login(email, password) {
  try {
    // create the url
    const url = createUrl('admin/login')

    // create the request body
    const body = {
      email,
      password,
    }

    // call the API
    const response = await axios.post(url, body)

    // get the response body
    return response.data
  } catch (ex) {
    return { status: 'error', error: ex }
  }
}

export async function getUserList() {
  try {
    const url = createUrl('user/all-users')
    const token = sessionStorage['token']
    const response = await axios.get(url, {
      headers: { token },
    })
    return response.data
  } catch (ex) {
    return { status: 'error', error: ex }
  }
}

export async function markActive(id) {
  try {
    const url = createUrl('user/make-active/' + id)
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

export async function markInactive(id) {
  try {
    const url = createUrl('user/make-inactive/' + id)
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
