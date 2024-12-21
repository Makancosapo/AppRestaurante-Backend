USE [master]
GO
/****** Object:  Database [Restaurante]    Script Date: 21/12/2024 14:40:19 ******/
CREATE DATABASE [Restaurante]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'Restaurante', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\Restaurante.mdf' , SIZE = 8192KB , MAXSIZE = UNLIMITED, FILEGROWTH = 65536KB )
 LOG ON 
( NAME = N'Restaurante_log', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\Restaurante_log.ldf' , SIZE = 8192KB , MAXSIZE = 2048GB , FILEGROWTH = 65536KB )
 WITH CATALOG_COLLATION = DATABASE_DEFAULT
GO
ALTER DATABASE [Restaurante] SET COMPATIBILITY_LEVEL = 150
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [Restaurante].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [Restaurante] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [Restaurante] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [Restaurante] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [Restaurante] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [Restaurante] SET ARITHABORT OFF 
GO
ALTER DATABASE [Restaurante] SET AUTO_CLOSE ON 
GO
ALTER DATABASE [Restaurante] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [Restaurante] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [Restaurante] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [Restaurante] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [Restaurante] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [Restaurante] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [Restaurante] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [Restaurante] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [Restaurante] SET  ENABLE_BROKER 
GO
ALTER DATABASE [Restaurante] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [Restaurante] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [Restaurante] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [Restaurante] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [Restaurante] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [Restaurante] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [Restaurante] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [Restaurante] SET RECOVERY SIMPLE 
GO
ALTER DATABASE [Restaurante] SET  MULTI_USER 
GO
ALTER DATABASE [Restaurante] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [Restaurante] SET DB_CHAINING OFF 
GO
ALTER DATABASE [Restaurante] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [Restaurante] SET TARGET_RECOVERY_TIME = 60 SECONDS 
GO
ALTER DATABASE [Restaurante] SET DELAYED_DURABILITY = DISABLED 
GO
ALTER DATABASE [Restaurante] SET ACCELERATED_DATABASE_RECOVERY = OFF  
GO
ALTER DATABASE [Restaurante] SET QUERY_STORE = OFF
GO
USE [Restaurante]
GO
/****** Object:  Table [dbo].[Menu]    Script Date: 21/12/2024 14:40:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Menu](
	[IdMenu] [int] IDENTITY(1,1) NOT NULL,
	[Nombre] [nvarchar](150) NOT NULL,
	[Precio] [decimal](10, 2) NOT NULL,
	[categoria] [nvarchar](50) NOT NULL,
	[descripcion] [nvarchar](500) NULL,
	[imgdir] [nvarchar](500) NULL,
	[flaginactivo] [bit] NOT NULL,
	[fechacreacion] [date] NULL,
	[fechamodificacion] [date] NULL,
	[Tiempopreparacion] [nvarchar](50) NULL,
 CONSTRAINT [PK__Menu__4D7EA8E10360EAB4] PRIMARY KEY CLUSTERED 
(
	[IdMenu] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MenuReceta]    Script Date: 21/12/2024 14:40:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MenuReceta](
	[IdMenu] [int] NOT NULL,
	[IdReceta] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[IdMenu] ASC,
	[IdReceta] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mesa]    Script Date: 21/12/2024 14:40:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mesa](
	[IdMesa] [int] IDENTITY(1,1) NOT NULL,
	[NumeroMesa] [int] NOT NULL,
	[Capacidad] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[IdMesa] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Pedido]    Script Date: 21/12/2024 14:40:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Pedido](
	[IdPedido] [int] IDENTITY(1,1) NOT NULL,
	[IdUsuario] [int] NOT NULL,
	[IdMesa] [int] NOT NULL,
	[FechaHora] [datetime] NOT NULL,
	[Total] [decimal](10, 2) NOT NULL,
	[estadopedido] [nvarchar](100) NULL,
PRIMARY KEY CLUSTERED 
(
	[IdPedido] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PedidoMenu]    Script Date: 21/12/2024 14:40:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PedidoMenu](
	[IdPedido] [int] NOT NULL,
	[IdMenu] [int] NOT NULL,
	[Cantidad] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[IdPedido] ASC,
	[IdMenu] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Productos]    Script Date: 21/12/2024 14:40:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Productos](
	[IdProducto] [int] IDENTITY(1,1) NOT NULL,
	[Nombre] [nvarchar](150) NOT NULL,
	[Stock] [int] NOT NULL,
	[Precio] [decimal](10, 2) NOT NULL,
	[IdProveedor] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[IdProducto] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Proveedores]    Script Date: 21/12/2024 14:40:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Proveedores](
	[IdProveedor] [int] IDENTITY(1,1) NOT NULL,
	[Nombre] [nvarchar](150) NOT NULL,
	[Telefono] [nvarchar](50) NULL,
	[Correo] [nvarchar](150) NULL,
PRIMARY KEY CLUSTERED 
(
	[IdProveedor] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Receta]    Script Date: 21/12/2024 14:40:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Receta](
	[IdReceta] [int] IDENTITY(1,1) NOT NULL,
	[Nombre] [nvarchar](150) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[IdReceta] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[RecetaProducto]    Script Date: 21/12/2024 14:40:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[RecetaProducto](
	[IdReceta] [int] NOT NULL,
	[IdProducto] [int] NOT NULL,
	[Cantidad] [decimal](10, 2) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[IdReceta] ASC,
	[IdProducto] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[usuarios]    Script Date: 21/12/2024 14:40:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[usuarios](
	[idusuario] [int] IDENTITY(1,1) NOT NULL,
	[username] [nvarchar](50) NULL,
	[nombre] [nvarchar](50) NOT NULL,
	[apellido] [nvarchar](50) NOT NULL,
	[correo] [nvarchar](50) NOT NULL,
	[rol] [nvarchar](50) NOT NULL,
	[password] [nvarchar](255) NOT NULL,
	[fechacreacion] [date] NOT NULL,
	[fechamodificacion] [date] NULL,
	[flageliminado] [bit] NOT NULL,
 CONSTRAINT [PK_usuarios] PRIMARY KEY CLUSTERED 
(
	[idusuario] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY],
UNIQUE NONCLUSTERED 
(
	[correo] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY],
UNIQUE NONCLUSTERED 
(
	[username] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
ALTER TABLE [dbo].[Pedido] ADD  DEFAULT (getdate()) FOR [FechaHora]
GO
ALTER TABLE [dbo].[MenuReceta]  WITH CHECK ADD  CONSTRAINT [FK__MenuRecet__IdMen__44FF419A] FOREIGN KEY([IdMenu])
REFERENCES [dbo].[Menu] ([IdMenu])
GO
ALTER TABLE [dbo].[MenuReceta] CHECK CONSTRAINT [FK__MenuRecet__IdMen__44FF419A]
GO
ALTER TABLE [dbo].[MenuReceta]  WITH CHECK ADD FOREIGN KEY([IdReceta])
REFERENCES [dbo].[Receta] ([IdReceta])
GO
ALTER TABLE [dbo].[Pedido]  WITH NOCHECK ADD FOREIGN KEY([IdMesa])
REFERENCES [dbo].[Mesa] ([IdMesa])
GO
ALTER TABLE [dbo].[Pedido]  WITH CHECK ADD FOREIGN KEY([IdUsuario])
REFERENCES [dbo].[usuarios] ([idusuario])
GO
ALTER TABLE [dbo].[PedidoMenu]  WITH CHECK ADD  CONSTRAINT [FK__PedidoMen__IdMen__52593CB8] FOREIGN KEY([IdMenu])
REFERENCES [dbo].[Menu] ([IdMenu])
GO
ALTER TABLE [dbo].[PedidoMenu] CHECK CONSTRAINT [FK__PedidoMen__IdMen__52593CB8]
GO
ALTER TABLE [dbo].[PedidoMenu]  WITH CHECK ADD FOREIGN KEY([IdPedido])
REFERENCES [dbo].[Pedido] ([IdPedido])
GO
ALTER TABLE [dbo].[Productos]  WITH CHECK ADD FOREIGN KEY([IdProveedor])
REFERENCES [dbo].[Proveedores] ([IdProveedor])
GO
ALTER TABLE [dbo].[RecetaProducto]  WITH CHECK ADD FOREIGN KEY([IdProducto])
REFERENCES [dbo].[Productos] ([IdProducto])
GO
ALTER TABLE [dbo].[RecetaProducto]  WITH CHECK ADD FOREIGN KEY([IdReceta])
REFERENCES [dbo].[Receta] ([IdReceta])
GO
USE [master]
GO
ALTER DATABASE [Restaurante] SET  READ_WRITE 
GO
