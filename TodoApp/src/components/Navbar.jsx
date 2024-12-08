import { Link, useNavigate } from 'react-router-dom'

function Navbar() {
  const navigate = useNavigate()

  const onLogout = () => {
    // remove the token
    sessionStorage.removeItem('token')

    // redirect to login page
    navigate('/login')
  }

  return (
    <div>
      <nav className='navbar navbar-expand-lg bg-primary' data-bs-theme='dark'>
        <div className='container-fluid'>
          <Link className='navbar-brand' to='/todo-item-list'>
            TodoApp
          </Link>

          <button
            className='navbar-toggler'
            type='button'
            data-bs-toggle='collapse'
            data-bs-target='#navbarSupportedContent'
            aria-controls='navbarSupportedContent'
            aria-expanded='false'
            aria-label='Toggle navigation'
          >
            <span className='navbar-toggler-icon'></span>
          </button>
          <div className='collapse navbar-collapse' id='navbarSupportedContent'>
            <ul className='navbar-nav me-auto mb-2 mb-lg-0'>
              <li className='nav-item'>
                <Link
                  to='/todo-item-list'
                  className='nav-link'
                  aria-current='page'
                >
                  Home
                </Link>
              </li>
              <li className='nav-item'>
                <Link to='/my-items' className='nav-link'>
                  My Items
                </Link>
              </li>
              <li className='nav-item'>
                <Link to='/add-item' className='nav-link'>
                  Add Item
                </Link>
              </li>
              <li className='nav-item'>
                <Link to='/profile' className='nav-link'>
                  Profile
                </Link>
              </li>
              <li className='nav-item'>
                <Link to='/change-password' className='nav-link'>
                  Change Password
                </Link>
              </li>
              <li className='nav-item'>
                <button onClick={onLogout} className='nav-link'>
                  Logout
                </button>
              </li>
            </ul>
          </div>
        </div>
      </nav>
    </div>
  )
}

export default Navbar
