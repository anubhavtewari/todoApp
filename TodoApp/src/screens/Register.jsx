import { useState } from 'react'
import { toast } from 'react-toastify'
import { register } from '../services/user'
import { Link, useNavigate } from 'react-router-dom'

function Register() {
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [email, setEmail] = useState('')
  const [phone, setPhone] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  // get the navigate function reference to navigate
  // from one to another component
  const navigate = useNavigate()

  const onRegister = async () => {
    if (firstName.length == 0) {
      toast.warning('Please enter first name')
    } else if (lastName.length == 0) {
      toast.warning('Please enter last name')
    } else if (email.length == 0) {
      toast.warning('Please enter email')
    } else if (phone.length == 0) {
      toast.warning('Please enter phone')
    } else if (password.length == 0) {
      toast.warning('Please enter password')
    } else if (confirmPassword.length == 0) {
      toast.warning('Please confirm password')
    } else if (password != confirmPassword) {
      toast.warning('Password does not match')
    } else {
      // call register function to consume register API
      const result = await register(firstName, lastName, email, phone, password)
      if (result['status'] == 'success') {
        toast.success('Successfully registered user')

        // dynamic navigation
        // navigate to login component
        navigate('/login')
      } else {
        toast.error(result['error'])
      }
    }
  }

  return (
    <div>
      <h2 className='heading'>Register</h2>

      <div className='row'>
        <div className='col-3'></div>
        <div className='col-6'>
          <div className='row'>
            <div className='col'>
              <div className='mb-3'>
                <label htmlFor=''>First Name</label>
                <input
                  onChange={(e) => setFirstName(e.target.value)}
                  type='text'
                  className='form-control'
                />
              </div>
            </div>
            <div className='col'>
              <div className='mb-3'>
                <label htmlFor=''>Last Name</label>
                <input
                  onChange={(e) => setLastName(e.target.value)}
                  type='text'
                  className='form-control'
                />
              </div>
            </div>
          </div>

          <div className='row'>
            <div className='col'>
              <div className='mb-3'>
                <label htmlFor=''>Email</label>
                <input
                  onChange={(e) => setEmail(e.target.value)}
                  type='text'
                  className='form-control'
                />
              </div>
            </div>
            <div className='col'>
              <div className='mb-3'>
                <label htmlFor=''>Phone Number</label>
                <input
                  onChange={(e) => setPhone(e.target.value)}
                  type='text'
                  className='form-control'
                />
              </div>
            </div>
          </div>

          <div className='row'>
            <div className='col'>
              <div className='mb-3'>
                <label htmlFor=''>Password</label>
                <input
                  onChange={(e) => setPassword(e.target.value)}
                  type='password'
                  className='form-control'
                />
              </div>
            </div>
            <div className='col'>
              <div className='mb-3'>
                <label htmlFor=''>Confirm Password</label>
                <input
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  type='password'
                  className='form-control'
                />
              </div>
            </div>
          </div>

          <div className='row'>
            <div className='col'>
              <div>
                Already have an account? <Link to='/login'>Login here</Link>
              </div>
              <button onClick={onRegister} className='btn btn-success mt-2'>
                Register
              </button>
            </div>
          </div>
        </div>
        <div className='col-3'></div>
      </div>
    </div>
  )
}

export default Register
