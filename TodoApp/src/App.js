import Login from './screens/Login'
import Register from './screens/Register'

import { ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import TodoItemList from './screens/TodoItemList'
import { Route, Routes } from 'react-router-dom'
import MyItems from './screens/MyItems'
import Profile from './screens/Profile'
import AddItem from './screens/AddItem'
import ChangePassword from './screens/ChagnePassword'

function App() {
  return (
    <div className='container-fluid'>
      <Routes>
        <Route path='/' element={<Login />} />
        <Route path='login' element={<Login />} />
        <Route path='register' element={<Register />} />
        <Route path='todo-item-list' element={<TodoItemList />} />
        <Route path='my-items' element={<MyItems />} />
        <Route path='profile' element={<Profile />} />
        <Route path='add-item' element={<AddItem />} />
        <Route path='change-password' element={<ChangePassword />} />
      </Routes>
      <ToastContainer />
    </div>
  )
}

export default App
