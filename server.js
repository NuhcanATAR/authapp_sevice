const express = require('express');
const app = express();
const authRoutes = require('./routes/auth'); 

app.use(express.json()); 

app.use('/api', authRoutes); 
const cors = require('cors');
app.use(cors());

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
