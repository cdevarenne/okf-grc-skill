from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated


class ListForm:
    # ruleid: drf-allowany
    permission_classes = [AllowAny]


class TupleForm:
    # ruleid: drf-allowany
    permission_classes = (IsAuthenticated, AllowAny)


# ruleid: drf-allowany
@api_view(["POST"])
@permission_classes([AllowAny])
def create_widget(request):
    return None


# ruleid: drf-allowany
@api_view(["POST"])
@permission_classes((AllowAny,))
def delete_widget(request):
    return None


class Authenticated:
    # ok: drf-allowany
    permission_classes = [IsAuthenticated]
