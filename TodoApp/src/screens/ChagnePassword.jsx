import { useState } from 'react'
import { toast } from 'react-toastify'
import { updatePassword } from '../services/user'
import Navbar from '../components/Navbar'

function ChangePassword() {
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  const onChangePassword = async () => {
    if (password.length == 0) {
      toast.warning('Please enter password')
    } else if (confirmPassword.length == 0) {
      toast.warning('Please confirm password')
    } else if (password != confirmPassword) {
      toast.warning('Password does not match')
    } else {
      // call register function to consume register API
      const result = await updatePassword(password)
      if (result['status'] == 'success') {
        toast.success('Successfully changed password')
      } else {
        toast.error(result['error'])
      }
    }
  }

  return (
    <div>
      <Navbar />
      <div className='container'>
        <h2 className='heading'>Change Password</h2>

        <div className='row'>
          <div className='col-3'></div>
          <div className='col-6'>
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
                <button
                  onClick={onChangePassword}
                  className='btn btn-success mt-2'
                >
                  Change Password
                </button>
              </div>
            </div>
          </div>
          <div className='col-3'></div>
        </div>
      </div>
    </div>
  )
}

export default ChangePassword
