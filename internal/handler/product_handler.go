package handler

import (
	"errors"
	"strconv"

	"shop-crud/internal/models"
	"shop-crud/internal/service"
	"shop-crud/pkg/response"

	"github.com/gin-gonic/gin"
)

type ProductHandler struct {
	service service.ProductService
}

func NewProductHandler(service service.ProductService) *ProductHandler {
	return &ProductHandler{service: service}
}

func (h *ProductHandler) RegisterRoutes(r *gin.RouterGroup) {
	products := r.Group("/products")
	{
		products.GET("", h.GetAll)
		products.GET("/:id", h.GetByID)
		products.POST("", h.Create)
		products.PUT("/:id", h.Update)
		products.DELETE("/:id", h.Delete)
	}
}

// GetAll godoc
// @Summary List all products
// @Description get all products
// @Tags products
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Router /products [get]
func (h *ProductHandler) GetAll(c *gin.Context) {
	products, err := h.service.GetAllProducts()
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	if products == nil {
		products = []models.Product{}
	}
	response.Success(c, products)
}

// GetByID godoc
// @Summary Get a product
// @Description get product by ID
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /products/{id} [get]
func (h *ProductHandler) GetByID(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid product ID")
		return
	}

	product, err := h.service.GetProductByID(id)
	if err != nil {
		if errors.Is(err, service.ErrProductNotFound) {
			response.NotFound(c, "Product not found")
			return
		}
		response.InternalError(c, err.Error())
		return
	}
	response.Success(c, product)
}

// Create godoc
// @Summary Create a product
// @Description create a new product
// @Tags products
// @Accept json
// @Produce json
// @Param product body models.CreateProductRequest true "Product data"
// @Success 201 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /products [post]
func (h *ProductHandler) Create(c *gin.Context) {
	var req models.CreateProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	product, err := h.service.CreateProduct(&req)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}
	response.Created(c, product)
}

// Update godoc
// @Summary Update a product
// @Description update product by ID
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Param product body models.UpdateProductRequest true "Product data"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /products/{id} [put]
func (h *ProductHandler) Update(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid product ID")
		return
	}

	var req models.UpdateProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	product, err := h.service.UpdateProduct(id, &req)
	if err != nil {
		if errors.Is(err, service.ErrProductNotFound) {
			response.NotFound(c, "Product not found")
			return
		}
		response.InternalError(c, err.Error())
		return
	}
	response.Success(c, product)
}

// Delete godoc
// @Summary Delete a product
// @Description delete product by ID
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /products/{id} [delete]
func (h *ProductHandler) Delete(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid product ID")
		return
	}

	if err := h.service.DeleteProduct(id); err != nil {
		if errors.Is(err, service.ErrProductNotFound) {
			response.NotFound(c, "Product not found")
			return
		}
		response.InternalError(c, err.Error())
		return
	}
	response.Deleted(c)
}
