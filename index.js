require('./db/mongoose')
const cors = require("cors");
const user = require('./routes/user')
const express = require('express')
const app = express()
app.use(express.json())
const port = process.env.POST || 3000;

app.use(cors());
app.use('/api',user);

app.listen(port, () => {
    console.log(`Server is up and running! on http://localhost:${port}`)
})