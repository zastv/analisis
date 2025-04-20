require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const { neon } = require('@neondatabase/serverless');
const { body, validationResult } = require('express-validator');



// Configuración inicial
const app = express();
const port = process.env.PORT || 3001;

// Conexión a Neon PostgreSQL
const sql = neon(process.env.DATABASE_URL);

app.get('/api/testdb', async (req, res) => {
  try {
    const result = await sql`SELECT 1 as test`;
    res.json({ success: true, result });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Primero servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// ... tus rutas API van aquí ...

// Fallback para rutas desconocidas que no sean API
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// Middleware
// Move these BEFORE any route definitions
app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));
app.options('*', cors()); // Soporte para preflight requests
app.use(express.static(path.join(__dirname, 'public')));

// Verificar conexión a la base de datos al iniciar
const initializeDatabase = async () => {
  try {
    // Crear tablas si no existen
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;

    await sql`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;

    await sql`
      CREATE TABLE IF NOT EXISTS carts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        status VARCHAR(20) DEFAULT 'active',
        UNIQUE(user_id)
      )
    `;

    await sql`
      CREATE TABLE IF NOT EXISTS cart_items (
        id SERIAL PRIMARY KEY,
        cart_id INTEGER REFERENCES carts(id) ON DELETE CASCADE,
        product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
        quantity INTEGER NOT NULL DEFAULT 1,
        added_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(cart_id, product_id)
      )
    `;

    console.log('✅ Tablas verificadas/creadas correctamente');
  } catch (error) {
    console.error('❌ Error al inicializar la base de datos:', error);
    process.exit(1); // Salir si hay error crítico en la DB
  }
};

// Update your registration route in server.js
app.post('/api/registrarse', [
  body('username').notEmpty().withMessage('El nombre de usuario es requerido'),
  body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres'),
  // Remove the email validation
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false,
      errors: errors.array() 
    });
  }

  try {
    const { username, password } = req.body;

    const [existingUser] = await sql`
      SELECT * FROM users WHERE username = ${username}
    `;
    
    if (existingUser) {
      return res.status(409).json({ 
        success: false,
        message: 'El usuario ya existe' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const [newUser] = await sql`
      INSERT INTO users (username, password)
      VALUES (${username}, ${hashedPassword})
      RETURNING id, username, created_at
    `;
    
    await sql`
      INSERT INTO carts (user_id) VALUES (${newUser.id})
    `;
    
    res.status(201).json({ 
      success: true,
      message: 'Usuario registrado con éxito',
      user: newUser 
    });
  } catch (error) {
    console.error('Error detallado en registro:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error en el servidor',
      error: error.message 
    });
  }
});

app.post('/api/login', [
  body('username').notEmpty().withMessage('Usuario es requerido'),
  body('password').notEmpty().withMessage('Contraseña es requerida'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false,
      errors: errors.array() 
    });
  }

  try {
    const { username, password } = req.body;

    const [user] = await sql`
      SELECT * FROM users WHERE username = ${username}
    `;
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: 'Credenciales inválidas' 
      });
    }
    
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ 
        success: false,
        message: 'Credenciales inválidas' 
      });
    }
    
    delete user.password;
    
    res.json({ 
      success: true,
      message: 'Inicio de sesión exitoso',
      user 
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error en el servidor',
      error: error.message 
    });
  }
});

// Rutas de productos
app.get('/api/products', async (req, res) => {
  try {
    const { category, search } = req.query;
    let query = sql`SELECT * FROM products WHERE 1=1`;
    
    if (category) {
      query = sql`${query} AND category = ${category}`;
    }
    
    if (search) {
      query = sql`${query} AND name ILIKE ${'%' + search + '%'}`;
    }
    
    const products = await query;
    res.json({ 
      success: true,
      data: products 
    });
  } catch (error) {
    console.error('Error al obtener productos:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error al obtener productos',
      error: error.message 
    });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const { name, price} = req.body;
    
    if (!name || !price) {
      return res.status(400).json({ 
        success: false,
        message: 'Nombre, precio son requeridos' 
      });
    }
    
    const [newProduct] = await sql`
      INSERT INTO products (name, price)
      VALUES (${name}, ${price})
      RETURNING *
    `;
    
    res.status(201).json({ 
      success: true,
      data: newProduct 
    });
  } catch (error) {
    console.error('Error al crear producto:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error al crear producto',
      error: error.message 
    });
  }
});

// Rutas del carrito
app.get('/api/cart', async (req, res) => {
  try {
    const { userId } = req.query;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false,
        message: 'ID de usuario es requerido' 
      });
    }
    
    const cartItems = await sql`
      SELECT 
        p.id, p.name, p.price AS subtotal
      FROM carts c
      JOIN cart_items ci ON c.id = ci.cart_id
      JOIN products p ON ci.product_id = p.id
      WHERE c.user_id = ${userId} AND c.status = 'active'
    `;
    
    const total = cartItems.reduce((sum, item) => sum + parseFloat(item.subtotal), 0);
    
    res.json({ 
      success: true,
      data: {
        items: cartItems,
        total: total.toFixed(2)
      }
    });
  } catch (error) {
    console.error('Error al obtener carrito:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error al obtener carrito',
      error: error.message 
    });
  }
});

app.post('/api/cart', async (req, res) => {
  try {
    const { userId, productId, quantity = 1 } = req.body;
    
    if (!userId || !productId) {
      return res.status(400).json({ 
        success: false,
        message: 'ID de usuario y producto son requeridos' 
      });
    }
    
    const product = await sql`
      SELECT * FROM products WHERE id = ${productId}
    `;
    
    if (!product) {
      return res.status(404).json({ 
        success: false,
        message: 'Producto no encontrado' 
      });
    }
    
    if (product.stock < quantity) {
      return res.status(400).json({ 
        success: false,
        message: 'No hay suficiente stock disponible' 
      });
    }
    
    let [cart] = await sql`
      SELECT * FROM carts 
      WHERE user_id = ${userId} AND status = 'active'
    `;
    
    if (!cart) {
      [cart] = await sql`
        INSERT INTO carts (user_id) 
        VALUES (${userId})
        RETURNING id
      `;
    }
    
    await sql`
      INSERT INTO cart_items (cart_id, product_id, quantity)
      VALUES (${cart.id}, ${productId}, ${quantity})
      ON CONFLICT (cart_id, product_id) 
      DO UPDATE SET quantity = cart_items.quantity + EXCLUDED.quantity
    `;
    
    res.status(201).json({ 
      success: true,
      message: 'Producto añadido al carrito' 
    });
  } catch (error) {
    console.error('Error al agregar al carrito:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error al actualizar carrito',
      error: error.message 
    });
  }
});

// Ruta para checkout
app.post('/api/checkout', async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false,
        message: 'ID de usuario es requerido' 
      });
    }
    
    await sql`BEGIN`;
    
    const [cart] = await sql`
      SELECT * FROM carts 
      WHERE user_id = ${userId} AND status = 'active'
      FOR UPDATE
    `;
    
    if (!cart) {
      await sql`ROLLBACK`;
      return res.status(404).json({ 
        success: false,
        message: 'No se encontró carrito activo' 
      });
    }
    
    const items = await sql`
      SELECT ci.product_id, ci.quantity, p.price
      FROM cart_items ci
      JOIN products p ON ci.product_id = p.id
      WHERE ci.cart_id = ${cart.id}
      FOR UPDATE
    `;
    
    for (const item of items) {
      if (item.quantity > item.stock) {
        await sql`ROLLBACK`;
        return res.status(400).json({ 
          success: false,
          message: `Stock insuficiente para el producto ID: ${item.product_id}` 
        });
      }
    }
    
    for (const item of items) {
      await sql`
        UPDATE products 
        SET stock = stock - ${item.quantity}
        WHERE id = ${item.product_id}
      `;
    }
    
    await sql`
      UPDATE carts 
      SET status = 'completed', updated_at = NOW()
      WHERE id = ${cart.id}
    `;
    
    await sql`
      INSERT INTO carts (user_id) 
      VALUES (${userId})
    `;
    
    await sql`COMMIT`;
    
    res.json({ 
      success: true,
      message: 'Compra realizada con éxito' 
    });
  } catch (error) {
    await sql`ROLLBACK`;
    console.error('Error en checkout:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error al procesar compra',
      error: error.message 
    });
  }
});

// Inicializar y arrancar el servidor
initializeDatabase().then(() => {
  app.listen(port, () => {
    console.log(`🚀 Servidor ejecutándose en http://localhost:${port}`);
  });
}).catch(error => {
  console.error('No se pudo iniciar la aplicación:', error);
  process.exit(1);
});

// Middleware de manejo de errores global
app.use((err, req, res, next) => {
  console.error('🔴 Error:', err);

  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Error en el servidor',
    // Opcional: enviar stack solo en desarrollo
    // stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});

// Captura de promesas no manejadas
process.on('unhandledRejection', (reason, promise) => {
  console.error('🚨 Unhandled Rejection at:', promise, '\nReason:', reason);
  // Opcional: podrías forzar el cierre del servidor si es crítico
  // process.exit(1);
});

// Captura de excepciones no manejadas
process.on('uncaughtException', (error) => {
  console.error('🔥 Uncaught Exception:', error);
  // En general se recomienda cerrar el proceso si ocurre esto
  process.exit(1);
});
