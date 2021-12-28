const jwt = require('jsonwebtoken');
const User = require('../models/Users');
const ErrorResponse = require ('../utils/errorResponse');

exports.protect = async (req, res, next) => {
    let token;
    //se le agrega Bearer delante para saber que es un token de autenticacion
    if(req.headers.authorization && req.headers.authorization.startsWith("Bearer")) { 
        //El token tiene la forma Bearer i4ht98ehg03rigj entonces si to separo por el espacio, la segunda parte del arreglo es el token propiamente dicho 
        token = req.headers.authorization.split(" ")[1]
    }
    if(!token) {
        return next(new ErrorResponse("Not authorized to access this route", 401))
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);

        if(!user) {
            return next(new ErrorResponse("No user was found with this id", 404))
        }

        req.user = user;

        next();
    } catch (error) {
        return next(new ErrorResponse("Not authorized to access this route", 401));
    }
}