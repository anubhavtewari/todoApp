import axios from 'axios'
import { createUrl } from '../utils'

export async function login(email, password) {
  try {
    // create the url
    const url = createUrl('user/login')

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

export async function register(firstName, lastName, email, phone, password) {
  try {
    const url = createUrl('user/register')
    const body = {
      firstName,
      lastName,
      email,
      phone,
      password,
    }
    const response = await axios.post(url, body)
    return response.data
  } catch (ex) {
    return { status: 'error', error: ex }
  }
}
export async function updatePassword(password) {
  try {
    const url = createUrl('user/update-password')
    const body = {
      password,
    }
    const token = sessionStorage['token']
    const response = await axios.put(url, body, {
      headers: { token },
    })
    return response.data
  } catch (ex) {
    return { status: 'error', error: ex }
  }
}

export async function getMyProfile() {
  try {
    const url = createUrl('user/profile')
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

export async function updateMyProfile(firstName, lastName, phone) {
  try {
    const url = createUrl('user/profile')
    const token = sessionStorage['token']
    const body = {
      firstName,
      lastName,
      phone,
    }
    const response = await axios.put(url, body, {
      headers: {
        token,
      },
    })
    return response.data
  } catch (ex) {
    return { status: 'error', error: ex }
  }
}
