import { useEffect, useState } from 'react'
import Navbar from '../components/Navbar'
import {
  getMyTodoItems,
  markItemPrivate,
  markItemPublic,
} from '../services/todo'
import { toast } from 'react-toastify'

function MyItems() {
  const [items, setItems] = useState([])

  const onLoadItems = async () => {
    const result = await getMyTodoItems()
    if (result['status'] == 'success') {
      setItems(result['data'])
    } else {
      toast.error(result['error'])
    }
  }

  useEffect(() => {
    onLoadItems()
  }, [])

  const onMarkPublic = async (id) => {
    const result = await markItemPublic(id)
    if (result['status'] == 'success') {
      toast.success('Successfully marked the item as public')

      // refresh the list
      onLoadItems()
    } else {
      toast.error(result['error'])
    }
  }

  const onMarkPrivate = async (id) => {
    const result = await markItemPrivate(id)
    if (result['status'] == 'success') {
      toast.success('Successfully marked the item as private')

      // refresh the list
      onLoadItems()
    } else {
      toast.error(result['error'])
    }
  }

  return (
    <div>
      <Navbar />

      <div className='container'>
        <h2 className='heading'>My Items</h2>

        {items.length == 0 && (
          <h5 className='heading'>There are no items added by you</h5>
        )}

        {items.length > 0 && (
          <table className='table table-hover'>
            <thead>
              <tr>
                <th>No.</th>
                <th>Title</th>
                <th>Details</th>
                <th>Date</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item, index) => {
                return (
                  <tr key={index}>
                    <td>{index + 1}</td>
                    <td>{item['title']}</td>
                    <td>{item['details']}</td>
                    <td>{item['createdTimestamp']}</td>
                    <td>
                      {item['isPublic'] == 0 && (
                        <button
                          onClick={() => onMarkPublic(item['id'])}
                          className='btn btn-success btn-sm'
                        >
                          make public
                        </button>
                      )}

                      {item['isPublic'] == 1 && (
                        <button
                          onClick={() => onMarkPrivate(item['id'])}
                          className='btn btn-warning btn-sm'
                        >
                          make private
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

export default MyItems
