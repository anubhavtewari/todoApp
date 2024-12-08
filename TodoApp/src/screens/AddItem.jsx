import { useState } from 'react'
import Navbar from '../components/Navbar'
import { toast } from 'react-toastify'
import { createTodoItem } from '../services/todo'
import { useNavigate } from 'react-router-dom'

function AddItem() {
  const [title, setTitle] = useState('')
  const [details, setDetails] = useState('')

  const navigate = useNavigate()

  const onAdd = async () => {
    if (title.length == 0) {
      toast.warning('Please enter title')
    } else if (details.length == 0) {
      toast.warning('Please enter details')
    } else {
      const result = await createTodoItem(title, details)
      if (result['status'] == 'success') {
        toast.success('Successfully added a new item')

        // redirect to my items
        navigate('/my-items')
      } else {
        toast.error(result['error'])
      }
    }
  }

  return (
    <div>
      <Navbar />
      <div className='container'>
        <h2 className='heading'>Add Todo Item</h2>
        <div className='mb-3'>
          <label htmlFor=''>Title</label>
          <input
            onChange={(e) => setTitle(e.target.value)}
            type='text'
            className='form-control'
          />
        </div>
        <div className='mb-3'>
          <label htmlFor=''>Details</label>
          <textarea
            onChange={(e) => setDetails(e.target.value)}
            rows={10}
            className='form-control'
          ></textarea>
        </div>

        <div className='mb-3'>
          <button onClick={onAdd} className='btn btn-success'>
            Add
          </button>
        </div>
      </div>
    </div>
  )
}

export default AddItem
