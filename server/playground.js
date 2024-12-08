function function1() {
  const person = {
    firstName: 'amit',
    lastName: 'kulkarni',
    email: 'amit@test.com',
    password: 'test',
    phone: '2324423412',
    address: 'pune',
  }

  // object destructuring
  // - create new variables using object properties

  // this line below will create firstName, lastName, email, password
  // and phone as variables having value from person object
  // corresponding to the property
  const { firstName, email, password, phone, lastName, age } = person

  console.log(`first name = ${firstName}`)
  console.log(`last name = ${lastName}`)
  console.log(`email = ${email}`)
  console.log(`phone = ${phone}`)
  console.log(`password = ${password}`)
  console.log(`age = ${age}`)
}

// function1()

function function2() {
  const numbers = [10, 20, 30]

  console.log(`1st = ${numbers[0]}`)
  console.log(`2nd = ${numbers[1]}`)
  console.log(`3rd = ${numbers[2]}`)

  // array destructuring
  // - create new variables using array values
  // - n1 = 10, n2 = 20, n3 = 30
  const [n1, n2, n3] = numbers
  console.log(`n1 = ${n1}, n2 = ${n2}, n3 = ${n3}`)
}

function2()
