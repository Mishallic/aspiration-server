const axios = require('axios')
for (let i = 0; i < 1000; i++) {
    axios.get('http://173.249.30.183/api/admin/allUsers').then(res => {

        console.log(res)
    }).catch(err => {
        console.log(err)
    })
}


