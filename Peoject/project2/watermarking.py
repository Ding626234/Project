import numpy as np
from PIL import Image
import cv2
import hashlib
import os
from typing import Tuple, Optional

class WatermarkingSystem:
    def __init__(self, secret_key: str = "default_key", alpha: float = 0.1):
        """
        初始化水印系统
        
        Args:
            secret_key: 用于生成水印的密钥
            alpha: 水印强度参数
        """
        self.secret_key = secret_key
        self.alpha = alpha
        
    def generate_watermark(self, shape: Tuple[int, int], seed: int) -> np.ndarray:
        """生成随机二值水印模式"""
        np.random.seed(seed)
        watermark = np.random.randint(0, 2, size=shape[:2])
        return watermark * 255  # 转换为0-255范围
    
    def embed_watermark(self, image_path: str, output_path: str, 
                        watermark_path: Optional[str] = None) -> None:
        """
        将水印嵌入到图像中
        
        Args:
            image_path: 原始图像路径
            output_path: 嵌入水印后图像的保存路径
            watermark_path: 水印图像路径，若为None则生成随机水印
        """
        # 读取原始图像
        img = cv2.imread(image_path)
        if img is None:
            raise FileNotFoundError(f"无法读取图像: {image_path}")
        
        # 生成或读取水印
        if watermark_path:
            watermark = cv2.imread(watermark_path, 0)
            if watermark is None:
                raise FileNotFoundError(f"无法读取水印图像: {watermark_path}")
            # 调整水印大小与原始图像一致
            watermark = cv2.resize(watermark, (img.shape[1], img.shape[0]))
            watermark = np.where(watermark > 127, 1, 0)
        else:
            # 从密钥生成种子
            seed = int(hashlib.md5(self.secret_key.encode()).hexdigest()[:8], 16)
            watermark = self.generate_watermark(img.shape, seed)
            watermark = watermark / 255  # 归一化到0-1
        
        # 转换图像到频域
        img_ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
        y, cr, cb = cv2.split(img_ycrcb)
        
        # 应用DCT变换
        dct_y = cv2.dct(np.float32(y))
        
        # 嵌入水印（在低频系数中）
        rows, cols = dct_y.shape
        watermark = cv2.resize(watermark, (cols, rows))
        watermarked_dct_y = dct_y + self.alpha * dct_y * watermark
        
        # 逆DCT变换
        watermarked_y = cv2.idct(watermarked_dct_y)
        watermarked_y = np.uint8(np.clip(watermarked_y, 0, 255))
        
        # 合并通道并保存
        watermarked_img_ycrcb = cv2.merge([watermarked_y, cr, cb])
        watermarked_img = cv2.cvtColor(watermarked_img_ycrcb, cv2.COLOR_YCrCb2BGR)
        cv2.imwrite(output_path, watermarked_img)
    
    def extract_watermark(self, watermarked_image_path: str, 
                         original_image_path: str) -> np.ndarray:
        """
        从水印图像中提取水印
        
        Args:
            watermarked_image_path: 嵌入水印的图像路径
            original_image_path: 原始图像路径
            
        Returns:
            提取的水印图像
        """
        # 读取图像
        watermarked_img = cv2.imread(watermarked_image_path)
        original_img = cv2.imread(original_image_path)
        
        if watermarked_img is None or original_img is None:
            raise FileNotFoundError("无法读取图像")
            
        # 确保图像尺寸一致
        watermarked_img = cv2.resize(watermarked_img, (original_img.shape[1], original_img.shape[0]))
        
        # 转换到YCrCb颜色空间
        watermarked_ycrcb = cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2YCrCb)
        original_ycrcb = cv2.cvtColor(original_img, cv2.COLOR_BGR2YCrCb)
        
        # 分离通道
        watermarked_y, _, _ = cv2.split(watermarked_ycrcb)
        original_y, _, _ = cv2.split(original_ycrcb)
        
        # 应用DCT变换
        dct_watermarked_y = cv2.dct(np.float32(watermarked_y))
        dct_original_y = cv2.dct(np.float32(original_y))
        
        # 提取水印
        extracted_watermark = (dct_watermarked_y - dct_original_y) / (self.alpha * dct_original_y)
        
        # 由于噪声影响，使用阈值处理
        extracted_watermark = np.where(extracted_watermark > 0.5, 255, 0).astype(np.uint8)
        
        return extracted_watermark
    
    def calculate_ncc(self, original_watermark: np.ndarray, 
                    extracted_watermark: np.ndarray) -> float:
        """计算归一化相关系数(NCC)评估水印提取质量"""
        # 调整大小以匹配
        extracted_watermark = cv2.resize(extracted_watermark, 
                                        (original_watermark.shape[1], original_watermark.shape[0]))
        
        # 归一化
        original_watermark = original_watermark.flatten().astype(np.float64)
        extracted_watermark = extracted_watermark.flatten().astype(np.float64)
        
        # 计算NCC
        numerator = np.sum(original_watermark * extracted_watermark)
        denominator = np.sqrt(np.sum(original_watermark**2) * np.sum(extracted_watermark**2))
        
        if denominator == 0:
            return 0
        
        return numerator / denominator


class RobustnessTester:
    def __init__(self, watermark_system: WatermarkingSystem):
        """初始化鲁棒性测试器"""
        self.watermark_system = watermark_system
    
    def test_rotation(self, watermarked_img_path: str, angle: float) -> np.ndarray:
        """测试旋转攻击"""
        img = cv2.imread(watermarked_img_path)
        rows, cols = img.shape[:2]
        M = cv2.getRotationMatrix2D((cols/2, rows/2), angle, 1)
        rotated_img = cv2.warpAffine(img, M, (cols, rows))
        return rotated_img
    
    def test_cropping(self, watermarked_img_path: str, crop_ratio: float) -> np.ndarray:
        """测试裁剪攻击"""
        img = cv2.imread(watermarked_img_path)
        rows, cols = img.shape[:2]
        cropped_img = img[int(rows*crop_ratio):int(rows*(1-crop_ratio)),
                         int(cols*crop_ratio):int(cols*(1-crop_ratio))]
        return cropped_img
    
    def test_contrast(self, watermarked_img_path: str, alpha: float) -> np.ndarray:
        """测试对比度调整攻击"""
        img = cv2.imread(watermarked_img_path)
        adjusted_img = cv2.convertScaleAbs(img, alpha=alpha, beta=0)
        return adjusted_img
    
    def test_blurring(self, watermarked_img_path: str, kernel_size: int) -> np.ndarray:
        """测试模糊攻击"""
        img = cv2.imread(watermarked_img_path)
        blurred_img = cv2.GaussianBlur(img, (kernel_size, kernel_size), 0)
        return blurred_img
    
    def run_all_tests(self, original_img_path: str, watermarked_img_path: str, 
                     original_watermark: np.ndarray, output_dir: str) -> dict:
        """运行所有鲁棒性测试并返回结果"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        tests = {
            "rotation_15": lambda: self.test_rotation(watermarked_img_path, 15),
            "rotation_30": lambda: self.test_rotation(watermarked_img_path, 30),
            "crop_01": lambda: self.test_cropping(watermarked_img_path, 0.1),
            "crop_02": lambda: self.test_cropping(watermarked_img_path, 0.2),
            "contrast_08": lambda: self.test_contrast(watermarked_img_path, 0.8),
            "contrast_12": lambda: self.test_contrast(watermarked_img_path, 1.2),
            "blur_3": lambda: self.test_blurring(watermarked_img_path, 3),
            "blur_5": lambda: self.test_blurring(watermarked_img_path, 5)
        }
        
        results = {}
        
        for test_name, test_func in tests.items():
            # 执行攻击
            attacked_img = test_func()
            attacked_img_path = os.path.join(output_dir, f"{test_name}.jpg")
            cv2.imwrite(attacked_img_path, attacked_img)
            
            # 提取水印
            try:
                extracted_watermark = self.watermark_system.extract_watermark(
                    attacked_img_path, original_img_path)
                
                # 计算NCC
                ncc = self.watermark_system.calculate_ncc(
                    original_watermark, extracted_watermark)
                
                results[test_name] = {
                    "ncc": ncc,
                    "extracted_watermark": extracted_watermark
                }
                
                # 保存提取的水印
                watermark_output_path = os.path.join(
                    output_dir, f"extracted_watermark_{test_name}.png")
                cv2.imwrite(watermark_output_path, extracted_watermark)
                
                print(f"{test_name}测试完成，NCC: {ncc:.4f}")
            except Exception as e:
                print(f"{test_name}测试失败: {str(e)}")
                results[test_name] = {"error": str(e)}
        
        return results


if __name__ == "__main__":
    # 示例用法
    secret_key = "your_secret_key_here"
    watermark_system = WatermarkingSystem(secret_key=secret_key, alpha=0.1)
    
    # 原始图像路径
    original_image_path = "lena.jpg"  # 请替换为实际图像路径
    
    # 嵌入水印
    watermarked_image_path = "watermarked_lena.jpg"
    watermark_system.embed_watermark(original_image_path, watermarked_image_path)
    
    # 提取水印
    extracted_watermark = watermark_system.extract_watermark(
        watermarked_image_path, original_image_path)
    cv2.imwrite("extracted_watermark.png", extracted_watermark)
    
    # 生成原始水印用于测试
    seed = int(hashlib.md5(secret_key.encode()).hexdigest()[:8], 16)
    original_watermark = watermark_system.generate_watermark(
        cv2.imread(original_image_path).shape, seed)
    
    # 鲁棒性测试
    tester = RobustnessTester(watermark_system)
    test_results = tester.run_all_tests(
        original_image_path, watermarked_image_path, 
        original_watermark, "robustness_tests")
    
    # 打印测试结果
    print("\n鲁棒性测试结果:")
    for test_name, result in test_results.items():
        if "ncc" in result:
            print(f"{test_name}: NCC = {result['ncc']:.4f}")
        else:
            print(f"{test_name}: 失败 - {result['error']}")    