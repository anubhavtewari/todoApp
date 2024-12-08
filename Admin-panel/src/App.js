import Login from './screens/Login'

import { ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import { Route, Routes } from 'react-router-dom'

import UserList from './screens/UserList'

function App() {
  return (
    <div className='container-fluid'>
      <Routes>
        <Route path='/' element={<Login />} />
        <Route path='login' element={<Login />} />
        <Route path='users' element={<UserList />} />
      </Routes>
      <ToastContainer />
    </div>
  )
}

export default App
