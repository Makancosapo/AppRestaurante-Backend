const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const { poolConnection, sql } = require('./db');
const cors = require('cors');
app.use(express.json());

const PORT = 8090;
const JWT_SECRET = 'your_secret_key'; // Cambia esto a un valor seguro

app.use(cors());
app.use(express.json());

app.listen(PORT, () => {
    console.log("Estamos vivos!");
});

// Obtener listado de usuarios
app.get('/users', async (req, res) => {
    try {
        const pool = await poolConnection;
        const resultado = await pool.request()
            .query(`
                SELECT idusuario, nombre, apellido, correo, rol, fechacreacion, fechamodificacion
                FROM usuarios WHERE flageliminado = 0
            `);
        res.json(resultado.recordset);
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al obtener los usuarios.');
    }
});

// Consultar usuario por ID
app.get('/users/:id', async (req, res) => {
    try {
        const pool = await poolConnection;
        const resultado = await pool.request()
            .input('idusuario', sql.Int, req.params.id)
            .query(`
                SELECT idusuario, nombre, apellido, correo, rol
                FROM usuarios
                WHERE idusuario = @idusuario AND flageliminado = 0
            `);
        if (resultado.recordset.length === 0) {
            return res.status(404).send('Usuario no encontrado.');
        }
        res.json(resultado.recordset[0]);
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al obtener el usuario.');
    }
});

// Crear usuario adm
app.post('/users', async (req, res) => {
    try {
        const { username,nombre, apellido, correo, rol, password } = req.body;
        if (!username||!nombre || !apellido || !correo || !rol || !password) {
            return res.status(400).send('Faltan campos requeridos.');
        }

        // Encriptar la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        const pool = await poolConnection;
        await pool.request()
            .input('username', sql.NVarChar, username)
            .input('nombre', sql.NVarChar, nombre)
            .input('apellido', sql.NVarChar, apellido)
            .input('correo', sql.NVarChar, correo)
            .input('rol', sql.NVarChar, rol)
            .input('password', sql.NVarChar, hashedPassword)
            .query(`
                INSERT INTO usuarios (username, nombre, apellido, correo, rol, password, fechacreacion, flageliminado)
                VALUES (@username,@nombre, @apellido, @correo, @rol, @password, GETDATE(), 0)
            `);
        res.status(201).send('Usuario creado.');
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al crear el usuario.');
    }
});

// Actualizar usuario: para usuarios ADMIN
app.put('/users/:id', async (req, res) => {
    try {
        const { nombre, apellido, correo, rol } = req.body;
        const idusuario = req.params.id;

        if (!nombre || !apellido || !correo || !rol) {
            return res.status(400).send('Faltan campos requeridos.');
        }

       
        const pool = await poolConnection;
        const resultado = await pool.request()
            .input('idusuario', sql.Int, idusuario)
            .input('nombre', sql.NVarChar, nombre)
            .input('apellido', sql.NVarChar, apellido)
            .input('correo', sql.NVarChar, correo)
            .input('rol', sql.NVarChar, rol)
            
            .query(`
                UPDATE usuarios
                SET 
                     nombre = @nombre
                    ,apellido = @apellido
                    ,correo = @correo
                    ,rol = @rol                    
                    ,fechamodificacion = GETDATE()
                WHERE idusuario = @idusuario
            `);

        if (resultado.rowsAffected[0] > 0) {
            return res.status(200).send('Usuario modificado.');
        }
        res.status(404).send('Usuario no encontrado.');
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al modificar el usuario.');
    }
});

// Eliminar usuario (lógico)
app.delete('/users/:id', async (req, res) => {
    try {
        const idusuario = req.params.id;

        const pool = await poolConnection;
        const resultado = await pool.request()
            .input('idusuario', sql.Int, idusuario)
            .query(`
                UPDATE usuarios
                SET flageliminado = 1, fechamodificacion = GETDATE()
                WHERE idusuario = @idusuario
            `);

        if (resultado.rowsAffected[0] > 0) {
            return res.status(200).send('Usuario eliminado.');
        }
        res.status(404).send('Usuario no encontrado.');
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al eliminar el usuario.');
    }
});

// Login 
app.post('/login', async (req, res) => {
    try {
        const { correo, password } = req.body;

        if (!correo || !password) {
            return res.status(400).send('Correo y contraseña son requeridos.');
        }

        const pool = await poolConnection;
        const resultado = await pool.request()
            .input('correo', sql.NVarChar, correo)
            .query(`
                SELECT idusuario, nombre, rol, password
                FROM usuarios
                WHERE correo = @correo AND flageliminado = 0
            `);

        if (resultado.recordset.length === 0) {
            return res.status(404).send('Usuario no encontrado.');
        }

        const usuario = resultado.recordset[0];
        const passwordMatch = await bcrypt.compare(password, usuario.password);

        if (!passwordMatch) {
            return res.status(401).send('Credenciales incorrectas.');
        }

        const token = jwt.sign(
            { idusuario: usuario.idusuario, rol: usuario.rol },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            message: 'Inicio de sesión exitoso.',
            token,
            usuario: { idusuario: usuario.idusuario, nombre: usuario.nombre, rol: usuario.rol }
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error en el inicio de sesión.');
    }
});

app.post('/newclient', async (req, res) => {
    try {
        const { username,nombre, apellido, correo, rol, password } = req.body;
        if (!username||!nombre || !apellido || !correo || !rol || !password) {
            return res.status(400).send('Faltan campos requeridos.');
        }

        // Encriptar la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        const pool = await poolConnection;
        await pool.request()
            .input('username', sql.NVarChar, username)
            .input('nombre', sql.NVarChar, nombre)
            .input('apellido', sql.NVarChar, apellido)
            .input('correo', sql.NVarChar, correo)
            .input('rol', sql.NVarChar, rol)
            .input('password', sql.NVarChar, hashedPassword)
            .query(`
                INSERT INTO usuarios (username, nombre, apellido, correo, rol, password, fechacreacion, flageliminado)
                VALUES (@username,@nombre, @apellido, @correo, 'cliente', @password, GETDATE(), 0)
            `);
        res.status(201).send('Usuario creado.');
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al crear el usuario.');
    }
});

//consultar menu

app.get('/menu-items', async (req, res) => {
    try {
        const pool = await poolConnection;
        const resultado = await pool.request()
            .query(`
                SELECT IdMenu,Nombre, Precio, categoria, descripcion, imgdir, Tiempopreparacion
                FROM Menu WHERE flaginactivo = 0
            `);
        res.json(resultado.recordset);
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al obtener los Menus.');
    }
});

//consultar menu por item

app.get('/menu/:id', async (req, res) => {
    try {
        const pool = await poolConnection;
        const resultado = await pool.request()
            .input('idmenu', sql.Int, req.params.id)
            .query(`
                SELECT idMenu, Nombre, Precio, categoria, descripcion, fechacreacion, Tiempopreparacion
                FROM Menu
                WHERE IdMenu = @idMenu AND flaginactivo = 0
            `);
        if (resultado.recordset.length === 0) {
            return res.status(404).send('Item del menu no encontrado.');
        }
        res.json(resultado.recordset[0]);
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al obtener el Item del menu.');
    }
});

//eliminar Item del menu

app.delete('/menu/:id', async (req, res) => {
    try {
        const IdMenu = req.params.id;

        const pool = await poolConnection;
        const resultado = await pool.request()
            .input('IdMenu', sql.Int, IdMenu)
            .query(`
                UPDATE Menu
                SET flaginactivo = 1, fechamodificacion = GETDATE()
                WHERE IdMenu = @idMenu
            `);

        if (resultado.rowsAffected[0] > 0) {
            return res.status(200).send('Item menu eliminado.');
        }
        res.status(404).send('Menu no encontrado.');
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al eliminar el Menu.');
    }
});



//Listado de pedidos
app.get('/pedidos', async (req, res) => {
    try {
        const pool = await poolConnection;
        const resultado = await pool.request()
            .query(`
                SELECT p.IdPedido
                ,u.nombre
                ,u.apellido
                ,p.IdMesa
                ,p.Total
                ,p.estadopedido 
                FROM Pedido p
                JOIN usuarios u 
                ON u.idusuario = p.IdUsuario
                WHERE u.flageliminado = 0
            `);
        res.json(resultado.recordset);
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al obtener los Menus.');
    }
});

//detallepedido

app.get('/pedido/:id', async (req, res) => {
    try {
        const pool = await poolConnection;
        const resultado = await pool.request()
            .input('idPedido', sql.Int, req.params.id)
            .query(`
              SELECT pm.IdPedido
                    ,u.nombre
                    ,u.apellido
                    ,m.categoria 
                    ,m.Nombre
                    ,m.Precio
                    ,pm.Cantidad 
              FROM PedidoMenu pm
              JOIN Menu m
              ON m.IdMenu = pm.IdMenu
              JOIN Pedido p
              ON p.IdPedido = pm.IdPedido
              JOIN usuarios u
              ON u.idusuario = p.IdUsuario
              WHERE pm.IdPedido = @idpedido
            `);
        if (resultado.recordset.length === 0) {
            return res.status(404).send('Pedido no encontrado.');
        }
        res.json(resultado.recordset[0]);
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al obtener el Pedido.');
    }
});


//crear nuevo item del menu

app.post('/newmenu', async (req, res) => {
    try {
        console.log(req.body); // Verifica los datos recibidos
        const { Nombre, Precio, categoria, descripcion, imgdir,Tiempopreparacion } = req.body;

        // Validación robusta de campos requeridos
        if (!Nombre || !Precio || !categoria || !descripcion || !Tiempopreparacion === undefined) {
            return res.status(400).send('Faltan campos requeridos.');
        }

        const pool = await poolConnection;
        await pool.request()
            .input('Nombre', sql.NVarChar, Nombre)
            .input('Precio', sql.Decimal(10, 2), Precio)
            .input('categoria', sql.NVarChar, categoria)
            .input('descripcion', sql.NVarChar, descripcion)
            .input('imgdir', sql.NVarChar, imgdir || '') // Maneja valores opcionales
            .input('Tiempopreparacion', sql.Int, Tiempopreparacion)

            .query(`
                INSERT INTO Menu (Nombre, Precio, categoria, descripcion, imgdir, Tiempopreparacion, fechacreacion, flaginactivo)
                VALUES (@Nombre, @Precio, @categoria, @descripcion, @imgdir,@Tiempopreparacion ,GETDATE(), 0)
            `);

        res.status(201).send('Ítem creado exitosamente.');
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Hubo un error al crear el ítem.');
    }
});




//actualizar item-menu

app.put('/menu/:id', async (req, res) => {
    try {
        const { Nombre, Precio, categoria, descripcion, imgdir,Tiempopreparacion } = req.body;
        const IdMenu = req.params.id;

        //if (!Nombre||!Precio || !categoria || !descripcion) {
        //    return res.status(400).send('Faltan campos requeridos.');
       //}

       
        const pool = await poolConnection;
        const resultado = await pool.request()
            .input('IdMenu', sql.NVarChar, IdMenu)
            .input('Nombre', sql.NVarChar, Nombre)
            .input('Precio', sql.Decimal(10,2), Precio)
            .input('categoria', sql.NVarChar, categoria)
            .input('descripcion', sql.NVarChar, descripcion)
            .input('imgdir', sql.NVarChar, imgdir)
            .input('Tiempopreparacion', sql.Int, Tiempopreparacion)
                
            .query(`
                UPDATE Menu
                SET 
                     Nombre = @Nombre
                    ,Precio = @Precio
                    ,categoria = @categoria
                    ,descripcion = @descripcion                  
                    ,imgdir = @imgdir
                    ,fechamodificacion =GETDATE()
                    ,Tiempopreparacion =@Tiempopreparacion
                WHERE idMenu = @idMenu
            `);

        if (resultado.rowsAffected[0] > 0) {
            return res.status(200).send('Usuario modificado.');
        }
        res.status(404).send('Usuario no encontrado.');
    } catch (error) {
        console.error(error);
        res.status(500).send('Hubo un error al modificar el usuario.');
    }
});







//crearpedido/// esta maaaliito

app.post('/pedido/iniciar', async (req, res) => {
    try {
        const { idusuario, Idmesa } = req.body; // Obtener los parámetros del body

        if (!idusuario || !Idmesa) {
            return res.status(400).send('Faltan parámetros requeridos: idusuario o idmesa.');
        }

        const pool = await poolConnection;

        // Insertar un nuevo pedido con valores predeterminados
        const resultado = await pool.request()
            .input('idusuario', sql.Int, idusuario)
            .input('Idmesa', sql.Int, Idmesa)
            .input('estadopedido', sql.NVarChar, 'Solicitado') // Estado predeterminado
            .query(`
                INSERT INTO Pedido (IdUsuario, IdMesa, FechaHora, Total, estadopedido)
                VALUES (@idusuario, @Idmesa, GETDATE(), 0, @estadopedido)
            `);

        const idpedido = resultado.recordset[0].IdPedido;

        res.status(201).send(`Pedido iniciado con ID: ${idpedido}`);
    } catch (error) {
        console.error('Error al iniciar el pedido:', error);
        res.status(500).send('Hubo un error al iniciar el pedido.');
    }
});
