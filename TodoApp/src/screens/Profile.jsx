import { Link } from 'react-router-dom'
import Navbar from '../components/Navbar'
import { useEffect, useState } from 'react'
import { getMyProfile, updateMyProfile } from '../services/user'
import { toast } from 'react-toastify'

function Profile() {
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [email, setEmail] = useState('')
  const [phone, setPhone] = useState('')

  const onLoadProfile = async () => {
    const result = await getMyProfile()
    if (result['status'] == 'success') {
      const data = result['data']
      console.log(data)
      setFirstName(data['firstName'])
      setLastName(data['lastName'])
      setEmail(data['email'])
      setPhone(data['phone'])
    }
  }

  const onSave = async () => {
    if (firstName.length == 0) {
      toast.warning('Please enter first name')
    } else if (lastName.length == 0) {
      toast.warning('Please enter last name')
    } else if (phone.length == 0) {
      toast.warning('Please enter phone')
    } else {
      const result = await updateMyProfile(firstName, lastName, phone)
      if (result['status'] == 'success') {
        toast.success('Successfully updated your profile')
      } else {
        toast.error(result['error'])
      }
    }
  }

  useEffect(() => {
    onLoadProfile()
  }, [])

  return (
    <div>
      <Navbar />

      <div className='container'>
        <h2 className='heading'>Profile</h2>
        <div className='row'>
          <div className='col'>
            <div className='mb-3'>
              <label htmlFor=''>First Name</label>
              <input
                value={firstName}
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
                value={lastName}
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
              <label htmlFor=''>Phone Number</label>
              <input
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                type='text'
                className='form-control'
              />
            </div>
          </div>
          <div className='col'>
            <div className='mb-3'>
              <label htmlFor=''>Email</label>
              <input
                readOnly
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                type='text'
                className='form-control'
              />
            </div>
          </div>
        </div>

        <div className='mb-3'>
          <button onClick={onSave} className='btn btn-success'>
            Update
          </button>
        </div>
      </div>
    </div>
  )
}

export default Profile
