import { useState } from 'react'
import { login } from '../services/user'
import { toast } from 'react-toastify'
import { Link, useNavigate } from 'react-router-dom'

function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  // get navigate function reference
  const navigate = useNavigate()

  const onLogin = async () => {
    // client side validation
    if (email.length == 0) {
      toast.warning('Please enter email')
    } else if (password.length == 0) {
      toast.warning('Please enter password')
    } else {
      // call the login api and get the result
      const result = await login(email, password)

      // check if the result is successful
      if (result['status'] == 'success') {
        // read the token from data
        const data = result['data']
        const token = data['token']

        // cache user token
        sessionStorage['token'] = token

        toast.success('welcome to the application')

        // redirect to todo item list
        navigate('/todo-item-list')
      } else {
        toast.error(result['error'])
      }
    }
  }

  return (
    <div>
      <h2 className='heading'>Login</h2>

      <div className='row'>
        <div className='col'></div>
        <div className='col'>
          <div className='mb-3'>
            <label htmlFor=''>Email</label>
            <input
              onChange={(e) => setEmail(e.target.value)}
              type='text'
              className='form-control'
            />
          </div>
          <div className='mb-3'>
            <label htmlFor=''>Password</label>
            <input
              onChange={(e) => setPassword(e.target.value)}
              type='password'
              className='form-control'
            />
          </div>
          <div className='mb-3'>
            <div>
              Don't have an account? <Link to='/register'>Register here</Link>
            </div>
            <div>
              Forgot password?{' '}
              <button className='btn btn-link'>Reset here.</button>
            </div>
            <button onClick={onLogin} className='btn btn-success mt-3'>
              Login
            </button>
          </div>
        </div>
        <div className='col'></div>
      </div>
    </div>
  )
}

export default Login
