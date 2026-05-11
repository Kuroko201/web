const mongoose = require('mongoose');

const user_data_schema = mongoose.Schema({
    name:{
        type: String,
        require: true

    },

    password:{
        type: String,
        require: true
    },

    
}, {timestamps: true});

const User_data = mongoose.model("User",user_data_schema);

module.exports = User_data;