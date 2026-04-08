package main

import (
	"database/sql"
	"log"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	_ "shop-crud/docs"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

var db *sql.DB

type Product struct {
	ID    int     `json:"id"      swag:"id,unique"`
	Name  string  `json:"name"    binding:"required"`
	Price float64 `json:"price"   binding:"required,gt=0"`
	Stock int     `json:"stock"   binding:"required,gte=0"`
}

// @title Shop Product API
// @version 1.0
// @description A simple CRUD API for shop products
// @host localhost:8080
// @BasePath /

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./shop.db")
	if err != nil {
		log.Fatal(err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		price REAL NOT NULL,
		stock INTEGER NOT NULL
	);`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}
}

// GetProducts godoc
// @Summary List all products
// @Description get all products
// @Tags products
// @Accept json
// @Produce json
// @Success 200 {array} Product
// @Router /products [get]
func getProducts(c *gin.Context) {
	rows, err := db.Query("SELECT id, name, price, stock FROM products")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Name, &p.Price, &p.Stock)
		products = append(products, p)
	}
	c.JSON(200, products)
}

// GetProduct godoc
// @Summary Get a product
// @Description get product by ID
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Success 200 {object} Product
// @Failure 404 {object} map[string]string
// @Router /products/{id} [get]
func getProduct(c *gin.Context) {
	id := c.Param("id")
	var p Product
	err := db.QueryRow("SELECT id, name, price, stock FROM products WHERE id = ?", id).
		Scan(&p.ID, &p.Name, &p.Price, &p.Stock)
	if err != nil {
		c.JSON(404, gin.H{"error": "Product not found"})
		return
	}
	c.JSON(200, p)
}

// CreateProduct godoc
// @Summary Create a product
// @Description create a new product
// @Tags products
// @Accept json
// @Produce json
// @Param product body Product true "Product data"
// @Success 201 {object} Product
// @Failure 400 {object} map[string]string
// @Router /products [post]
func createProduct(c *gin.Context) {
	var p Product
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	result, err := db.Exec("INSERT INTO products (name, price, stock) VALUES (?, ?, ?)", p.Name, p.Price, p.Stock)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	id, _ := result.LastInsertId()
	p.ID = int(id)
	c.JSON(201, p)
}

// UpdateProduct godoc
// @Summary Update a product
// @Description update product by ID
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Param product body Product true "Product data"
// @Success 200 {object} Product
// @Failure 400 {object} map[string]string
// @Router /products/{id} [put]
func updateProduct(c *gin.Context) {
	id := c.Param("id")
	var p Product
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	result, err := db.Exec("UPDATE products SET name = ?, price = ?, stock = ? WHERE id = ?", p.Name, p.Price, p.Stock, id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		c.JSON(404, gin.H{"error": "Product not found"})
		return
	}
	c.JSON(200, p)
}

// DeleteProduct godoc
// @Summary Delete a product
// @Description delete product by ID
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Success 200 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /products/{id} [delete]
func deleteProduct(c *gin.Context) {
	id := c.Param("id")
	result, err := db.Exec("DELETE FROM products WHERE id = ?", id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		c.JSON(404, gin.H{"error": "Product not found"})
		return
	}
	c.JSON(200, gin.H{"message": "Product deleted"})
}

func main() {
	initDB()
	defer db.Close()

	r := gin.Default()

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.GET("/products", getProducts)
	r.GET("/products/:id", getProduct)
	r.POST("/products", createProduct)
	r.PUT("/products/:id", updateProduct)
	r.DELETE("/products/:id", deleteProduct)

	log.Println("Server running on :8080")
	log.Println("Swagger UI: http://localhost:8080/swagger/index.html")
	r.Run(":8080")
}


