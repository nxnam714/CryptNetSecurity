//TODO: Write functions which has not been included in Labs to encrypt or decrypt the input file.
#include <opencv/highgui.h>

using namespace cv;

void steganography_encode(char* inputfile, Mat image, char*outputfile);
void steganography_decode(Mat image, char*outputfile);
