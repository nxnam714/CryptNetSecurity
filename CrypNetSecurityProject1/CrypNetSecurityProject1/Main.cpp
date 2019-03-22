#include <iostream>
#include "Addition.h"
#include "Asymmetric.h"
#include "Symmetric.h"


#define SYMMETRIC_ENCODE	10
#define SYMMETRIC_DECODE	11
#define ASYMMETRIC_ENCODE	20
#define ASYMMETRIC_DECODE	21
#define STREGAN_ENCODE		30
#define STREGAN_DECODE		31


using namespace std;

int main(int argc, char *argv[])
{
	int tasks = 0;
	if (argc > 1) {
		sscanf(argv[1], "%d", &tasks);
	}
	else
	{
		return 0;
	}
	switch (tasks)
	{
	case 30:
	{
		Mat image = imread(argv[3]);
		steganography_encode(argv[2], image, argv[4]);
		break;
	}
	case 31:
	{
		Mat cipherImage = imread(argv[2]);
		steganography_decode(cipherImage, argv[3]);
	}
	default:
		return 0;
	}
	//char image_file[] = "../input_files/dennis_ritchie.png";
	//char text[] = "../input_files/text.txt";
	//char outImage[] = "../output_files/output_image.png";
	//char plaintText[] = "../output_files/plainttext.txt";
	system("pause");
	return 0;
}