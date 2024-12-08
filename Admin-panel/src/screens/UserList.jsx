import { useEffect, useState } from 'react'
import Navbar from '../components/Navbar'

import { toast } from 'react-toastify'
import { getUserList, markActive, markInactive } from '../services/user'

function UserList() {
  const [users, setUsers] = useState([])

  const onLoadUsers = async () => {
    const result = await getUserList()
    console.log(result)
    if (result['status'] == 'success') {
      setUsers(result['data'])
    } else {
      toast.error(result['error'])
    }
  }

  useEffect(() => {
    onLoadUsers()
  }, [])

  const onToggle = async (id, status) => {
    let result
    if (status == 1) {
      result = await markActive(id)
    } else {
      result = await markInactive(id)
    }

    if (result['status'] == 'success') {
      toast.success('Successfully updated status')
      onLoadUsers()
    } else {
      toast.error(result['error'])
    }
  }

  return (
    <div>
      <Navbar />

      <div className='container'>
        <h2 className='heading'>Users</h2>

        {users.length == 0 && <h5 className='heading'>There are no users </h5>}

        {users.length > 0 && (
          <table className='table table-hover'>
            <thead>
              <tr>
                <th>No.</th>
                <th>First Name</th>
                <th>Last Name</th>
                <th>Email</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user, index) => {
                return (
                  <tr key={index}>
                    <td>{index + 1}</td>
                    <td>{user['firstName']}</td>
                    <td>{user['lastName']}</td>
                    <td>{user['email']}</td>
                    <td>{user['isActive']}</td>
                    <td>
                      {user['isActive'] == 0 && (
                        <button
                          onClick={() => onToggle(user['id'], 1)}
                          className='btn btn-success btn-sm'
                        >
                          make active
                        </button>
                      )}

                      {user['isActive'] == 1 && (
                        <button
                          onClick={() => onToggle(user['id'], 0)}
                          className='btn btn-warning btn-sm'
                        >
                          make inactive
                        </button>
                      )}

                      <button className='btn btn-danger btn-sm ms-2'>
                        delete
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

export default UserList
