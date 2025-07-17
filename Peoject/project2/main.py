import os
import cv2
import numpy as np
from watermarking import WatermarkingSystem, RobustnessTester
import matplotlib.pyplot as plt

def main():
    # 创建输出目录
    if not os.path.exists("output"):
        os.makedirs("output")
    
    # 初始化水印系统
    secret_key = "SecureWatermarkKey2025"
    watermark_system = WatermarkingSystem(secret_key=secret_key, alpha=0.1)
    
    # 准备测试图像
    # 使用OpenCV自带的测试图像或提供的示例图像
    try:
        # 尝试使用OpenCV的示例图像
        img_path = cv2.samples.findFile("lena.jpg")
        if not img_path:
            raise FileNotFoundError
    except:
        # 如果没有找到，创建一个简单的测试图像
        img = np.ones((512, 512, 3), dtype=np.uint8) * 200
        cv2.putText(img, "Test Image", (100, 256), 
                   cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 2)
        img_path = "test_image.jpg"
        cv2.imwrite(img_path, img)
    
    # 嵌入水印
    original_image_path = img_path
    watermarked_image_path = "output/watermarked_image.jpg"
    watermark_system.embed_watermark(original_image_path, watermarked_image_path)
    
    # 直接提取水印（无攻击）
    extracted_watermark = watermark_system.extract_watermark(
        watermarked_image_path, original_image_path)
    cv2.imwrite("output/extracted_watermark_original.png", extracted_watermark)
    
    # 生成原始水印用于评估
    seed = int(hashlib.md5(secret_key.encode()).hexdigest()[:8], 16)
    original_img = cv2.imread(original_image_path)
    original_watermark = watermark_system.generate_watermark(original_img.shape, seed)
    
    # 计算原始NCC
    original_ncc = watermark_system.calculate_ncc(original_watermark, extracted_watermark)
    print(f"原始提取NCC: {original_ncc:.4f}")
    
    # 鲁棒性测试
    tester = RobustnessTester(watermark_system)
    test_results = tester.run_all_tests(
        original_image_path, watermarked_image_path, 
        original_watermark, "output/robustness_tests")
    
    # 可视化结果
    visualize_results(original_image_path, watermarked_image_path, test_results)

def visualize_results(original_path, watermarked_path, test_results):
    """可视化水印嵌入和鲁棒性测试结果"""
    # 创建一个大的图像展示
    plt.figure(figsize=(12, 10))
    
    # 显示原始图像
    plt.subplot(3, 3, 1)
    original_img = cv2.imread(original_path)
    original_img = cv2.cvtColor(original_img, cv2.COLOR_BGR2RGB)
    plt.imshow(original_img)
    plt.title("原始图像")
    plt.axis('off')
    
    # 显示水印图像
    plt.subplot(3, 3, 2)
    watermarked_img = cv2.imread(watermarked_path)
    watermarked_img = cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2RGB)
    plt.imshow(watermarked_img)
    plt.title("水印图像")
    plt.axis('off')
    
    # 显示几个关键测试结果
    test_keys = list(test_results.keys())
    for i, test_key in enumerate(test_keys[:6], start=3):
        plt.subplot(3, 3, i)
        result = test_results[test_key]
        
        if "ncc" in result:
            attacked_img = cv2.imread(f"output/robustness_tests/{test_key}.jpg")
            attacked_img = cv2.cvtColor(attacked_img, cv2.COLOR_BGR2RGB)
            plt.imshow(attacked_img)
            plt.title(f"{test_key}\nNCC: {result['ncc']:.4f}")
        else:
            plt.text(0.5, 0.5, f"{test_key}\n测试失败", 
                    horizontalalignment='center', verticalalignment='center')
        plt.axis('off')
    
    plt.tight_layout()
    plt.savefig("output/watermark_test_summary.png")
    plt.close()

if __name__ == "__main__":
    main()    