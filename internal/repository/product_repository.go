package repository

import (
	"database/sql"
	"errors"
	"time"

	"shop-crud/internal/models"
)

var ErrNotFound = errors.New("record not found")

type ProductRepository interface {
	GetAll() ([]models.Product, error)
	GetByID(id int) (*models.Product, error)
	Create(product *models.Product) error
	Update(id int, product *models.Product) error
	Delete(id int) error
}

type productRepository struct {
	db *sql.DB
}

func NewProductRepository(db *sql.DB) ProductRepository {
	return &productRepository{db: db}
}

func (r *productRepository) GetAll() ([]models.Product, error) {
	rows, err := r.db.Query(`
		SELECT id, name, price, stock, created_at, updated_at 
		FROM products ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []models.Product
	for rows.Next() {
		var p models.Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Price, &p.Stock, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		products = append(products, p)
	}
	return products, rows.Err()
}

func (r *productRepository) GetByID(id int) (*models.Product, error) {
	var p models.Product
	err := r.db.QueryRow(`
		SELECT id, name, price, stock, created_at, updated_at 
		FROM products WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.Price, &p.Stock, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

func (r *productRepository) Create(product *models.Product) error {
	now := time.Now()
	product.CreatedAt = now
	product.UpdatedAt = now

	result, err := r.db.Exec(`
		INSERT INTO products (name, price, stock, created_at, updated_at) 
		VALUES (?, ?, ?, ?, ?)`,
		product.Name, product.Price, product.Stock, product.CreatedAt, product.UpdatedAt)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	product.ID = int(id)
	return nil
}

func (r *productRepository) Update(id int, product *models.Product) error {
	product.UpdatedAt = time.Now()
	result, err := r.db.Exec(`
		UPDATE products SET name = ?, price = ?, stock = ?, updated_at = ? 
		WHERE id = ?`,
		product.Name, product.Price, product.Stock, product.UpdatedAt, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	product.ID = id
	return nil
}

func (r *productRepository) Delete(id int) error {
	result, err := r.db.Exec("DELETE FROM products WHERE id = ?", id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}
