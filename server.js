const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;



// Conexión a MongoDB con opciones actualizadas
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/mi-base-de-datos', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('Conectado a MongoDB'))
  .catch((error) => {
    console.error('Error al conectar a MongoDB:', error);
    process.exit(1);
  });

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3001',
  credentials: true,
}));

// Servir archivos estáticos (corregido para evitar duplicación)
app.use(express.static(path.join(__dirname, 'public')));

// Modelos
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}));

const Product = mongoose.model('Product', new mongoose.Schema({
  _id: Number,
  name: String,
  price: Number,
  description: String,
  stock: Number,
}));

const Cart = mongoose.model('Cart', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
  products: [{
    productId: { type: Number, required: true },
    quantity: { type: Number, required: true },
  }],
}));

// Implementación completa de las rutas de autenticación
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Verificar si el usuario ya existe
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }
    
    // Encriptar contraseña
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Crear nuevo usuario
    const newUser = new User({
      username,
      password: hashedPassword
    });
    
    await newUser.save();
    res.status(201).json({ message: 'Usuario registrado con éxito' });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Buscar usuario
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    
    // Verificar contraseña
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    
    // Aquí deberías implementar JWT o sesiones
    // Por simplicidad, solo enviamos el ID del usuario
    res.json({ 
      message: 'Inicio de sesión exitoso',
      userId: user._id
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

// Rutas del carrito
app.post('/cart', async (req, res) => {
  try {
    const { userId, productId, quantity } = req.body;
    
    // Verificar que el producto exista
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ message: 'Producto no encontrado' });
    }
    
    // Verificar stock
    if (product.stock < quantity) {
      return res.status(400).json({ message: 'No hay suficiente stock' });
    }
    
    // Buscar o crear carrito
    let cart = await Cart.findOne({ userId });
    if (!cart) {
      cart = new Cart({ userId, products: [] });
    }
    
    // Verificar si el producto ya está en el carrito
    const existingProductIndex = cart.products.findIndex(item => item.productId === productId);
    
    if (existingProductIndex >= 0) {
      // Actualizar cantidad
      cart.products[existingProductIndex].quantity += quantity;
    } else {
      // Añadir nuevo producto
      cart.products.push({ productId, quantity });
    }
    
    await cart.save();
    res.status(201).json({ message: 'Producto añadido al carrito', cart });
  } catch (error) {
    console.error('Error al agregar al carrito:', error);
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.get('/cart', async (req, res) => {
  try {
    const { userId } = req.query;
    
    if (!userId) {
      return res.status(400).json({ message: 'Se requiere userId' });
    }
    
    const cart = await Cart.findOne({ userId });
    if (!cart) {
      return res.json({ products: [] });
    }
    
    // Obtener información detallada de productos
    const populatedCart = [];
    for (const item of cart.products) {
      const product = await Product.findById(item.productId);
      if (product) {
        populatedCart.push({
          product,
          quantity: item.quantity
        });
      }
    }
    
    res.json({ products: populatedCart });
  } catch (error) {
    console.error('Error al obtener carrito:', error);
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});



// API endpoints para productos
app.get('/api/productos', async (req, res) => {
  try {
    const productos = await Product.find();
    res.json(productos);
  } catch (error) {
    console.error('Error al obtener productos:', error);
    res.status(500).json({ message: 'Error al obtener productos', error: error.message });
  }
});

// Ruta principal con selector de interfaz
app.get('/', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const isMobile = /mobile|android|iphone|ipad|phone/i.test(userAgent.toLowerCase());

  if (req.query.interface === 'mobile') {
    return res.sendFile(path.join(__dirname, 'public', 'mobile.html'));
  } else if (req.query.interface === 'web') {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }

  // Redirección automática para móviles
  if (isMobile && !req.query.noredirect) {
    return res.sendFile(path.join(__dirname, 'public', 'mobile.html'));
  }

  // Página principal por defecto
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// Iniciar servidor
app.listen(port, '0.0.0.0', () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});